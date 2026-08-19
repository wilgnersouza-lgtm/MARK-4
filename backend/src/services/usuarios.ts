import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { config } from '../config';

export interface Usuario {
  id: string;
  email: string;
  nome: string;
  senhaHash: string;
  criadoEm: string;
  ultimoAcesso: string | null;
  ativo: boolean;
  /** Token de redefinição de senha e seu vencimento */
  tokenRecuperacao?: string | null;
  tokenExpiraEm?: string | null;
}

interface BaseUsuarios {
  usuarios: Usuario[];
}

const CUSTO_HASH = 10;
const VALIDADE_TOKEN_MINUTOS = 30;

/**
 * Cadastro de usuários com senha em hash bcrypt.
 *
 * A persistência é em arquivo JSON — suficiente para uso interno e para
 * substituir a autenticação simulada, mas NÃO é um banco de dados: não há
 * transações nem controle de concorrência. Para produção com vários usuários
 * simultâneos, troque a implementação de `ler`/`gravar` por um banco real
 * mantendo a mesma interface pública desta classe.
 */
export class UsuarioService {
  private caminho: string;

  constructor() {
    const dir = fs.existsSync(config.dataDir) ? config.dataDir : process.cwd();
    this.caminho = path.join(dir, 'usuarios.json');
  }

  private ler(): BaseUsuarios {
    if (!fs.existsSync(this.caminho)) {
      return { usuarios: [] };
    }
    try {
      return JSON.parse(fs.readFileSync(this.caminho, 'utf-8'));
    } catch {
      return { usuarios: [] };
    }
  }

  private gravar(base: BaseUsuarios) {
    fs.writeFileSync(this.caminho, JSON.stringify(base, null, 2), 'utf-8');
  }

  private normalizar(email: string): string {
    return email.trim().toLowerCase();
  }

  /** Remove o hash e os tokens antes de devolver o usuário para fora */
  private publico(u: Usuario) {
    return {
      userId: u.id,
      email: u.email,
      nome: u.nome,
      criadoEm: u.criadoEm,
      ultimoAcesso: u.ultimoAcesso,
    };
  }

  existeAlgum(): boolean {
    return this.ler().usuarios.length > 0;
  }

  buscarPorEmail(email: string): Usuario | null {
    const alvo = this.normalizar(email);
    return this.ler().usuarios.find(u => u.email === alvo) || null;
  }

  /**
   * Cria um usuário. A senha nunca é armazenada em texto puro.
   */
  async criar(email: string, senha: string, nome?: string) {
    const alvo = this.normalizar(email);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(alvo)) {
      throw new Error('E-mail inválido.');
    }
    if (!senha || senha.length < 8) {
      throw new Error('A senha deve ter ao menos 8 caracteres.');
    }

    const base = this.ler();
    if (base.usuarios.some(u => u.email === alvo)) {
      throw new Error('Já existe uma conta com este e-mail.');
    }

    const usuario: Usuario = {
      id: crypto.randomUUID(),
      email: alvo,
      nome: nome?.trim() || alvo.split('@')[0],
      senhaHash: await bcrypt.hash(senha, CUSTO_HASH),
      criadoEm: new Date().toISOString(),
      ultimoAcesso: null,
      ativo: true,
    };

    base.usuarios.push(usuario);
    this.gravar(base);

    return this.publico(usuario);
  }

  /**
   * Valida e-mail e senha.
   *
   * A mensagem de erro é a mesma para e-mail inexistente e senha errada, de
   * propósito: distinguir os dois casos permite descobrir quais e-mails têm
   * conta no sistema.
   */
  async autenticar(email: string, senha: string) {
    const usuario = this.buscarPorEmail(email);

    if (!usuario || !usuario.ativo) {
      // Compara mesmo assim, para o tempo de resposta não denunciar a diferença
      await bcrypt.compare(senha || '', '$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinv');
      throw new Error('E-mail ou senha incorretos.');
    }

    const confere = await bcrypt.compare(senha || '', usuario.senhaHash);
    if (!confere) {
      throw new Error('E-mail ou senha incorretos.');
    }

    const base = this.ler();
    const registro = base.usuarios.find(u => u.id === usuario.id)!;
    registro.ultimoAcesso = new Date().toISOString();
    this.gravar(base);

    return this.publico(registro);
  }

  /**
   * Gera token de redefinição de senha.
   *
   * Devolve sempre sucesso, mesmo para e-mail inexistente, para não revelar
   * quais endereços possuem conta.
   */
  solicitarRecuperacao(email: string) {
    const usuario = this.buscarPorEmail(email);

    if (!usuario) {
      return { enviado: true, token: null as string | null };
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expira = new Date(Date.now() + VALIDADE_TOKEN_MINUTOS * 60_000).toISOString();

    const base = this.ler();
    const registro = base.usuarios.find(u => u.id === usuario.id)!;
    registro.tokenRecuperacao = crypto.createHash('sha256').update(token).digest('hex');
    registro.tokenExpiraEm = expira;
    this.gravar(base);

    // O envio por e-mail depende de SMTP configurado, que este projeto não tem.
    // Em desenvolvimento o token volta na resposta; em produção ele deve ser
    // enviado por e-mail e NUNCA retornado pela API.
    return {
      enviado: true,
      token: config.isProd ? null : token,
      expiraEm: expira,
    };
  }

  async redefinirSenha(token: string, novaSenha: string) {
    if (!novaSenha || novaSenha.length < 8) {
      throw new Error('A senha deve ter ao menos 8 caracteres.');
    }

    const hashToken = crypto.createHash('sha256').update(token).digest('hex');
    const base = this.ler();
    const registro = base.usuarios.find(u => u.tokenRecuperacao === hashToken);

    if (!registro) {
      throw new Error('Token inválido ou já utilizado.');
    }
    if (!registro.tokenExpiraEm || new Date(registro.tokenExpiraEm) < new Date()) {
      throw new Error('Token expirado. Solicite a redefinição novamente.');
    }

    registro.senhaHash = await bcrypt.hash(novaSenha, CUSTO_HASH);
    registro.tokenRecuperacao = null;
    registro.tokenExpiraEm = null;
    this.gravar(base);

    return this.publico(registro);
  }

  async alterarSenha(email: string, senhaAtual: string, novaSenha: string) {
    await this.autenticar(email, senhaAtual);

    if (!novaSenha || novaSenha.length < 8) {
      throw new Error('A nova senha deve ter ao menos 8 caracteres.');
    }

    const base = this.ler();
    const registro = base.usuarios.find(u => u.email === this.normalizar(email))!;
    registro.senhaHash = await bcrypt.hash(novaSenha, CUSTO_HASH);
    this.gravar(base);

    return this.publico(registro);
  }
}

export const usuarioService = new UsuarioService();
