import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {configuracionSeguridad} from '../config/seguridad.config';
import {Credenciales, FactorDeAutenticacionPorCodigo, Usuario} from '../models';
import {LoginRepository, UsuarioRepository} from '../repositories';
const generator = require('generate-password');
const MD5 = require("crypto-js/md5");
const jwt = require('jsonwebtoken');


@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) {}

  /**
   * crear una clave aleatoria
   * @returns cadena aleatoria de n caracteres
   */

  crearTextoAleatorio(n:number): string{
    let clave = generator.generate({
      length: n,
      numbers: true
    });
    return clave
  }

  /**
   * cifrar una cadena con md5
   * @param cadena texto a cifrar
   * @returns cadena cifrada con md5
   */

  cifrarTexto(cadena: string): string{
    let cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

  /**
   * se busca un usuario por sus credenciales de acceso
   * @param credenciales credenciales de usuario
   * @returns usuario encontrado o null
   */

  async identificarUsuario(credenciales: Credenciales):Promise<Usuario|null>{
    let usuario = await this.repositorioUsuario.findOne({
      where:{
        correo: credenciales.correo,
        clave: credenciales.clave
      }
    });
    return usuario as Usuario;
  }
  /**
   * valida un codigo de 2fa para un usuario
   * @param credenciales2fa credenciales del usuario con el codigo 2fa
   * @returns el registro del login o null
   */
  async validarCodigo2fa(credenciales2fa: FactorDeAutenticacionPorCodigo): Promise<Usuario|null>{
    let login = await this.repositorioLogin.findOne({
      where: {
        usuarioId: credenciales2fa.usuarioId,
        codigo2fa: credenciales2fa.codigo2fa,
        estadoCodigo2fa: false
      }
    });
    if(login){
      let usuario = await this.repositorioUsuario.findById(credenciales2fa.usuarioId);
      return usuario
    }
    return null
  }

  /**
   * generacion de JWT
   * @param usuario informacion del usuario
   * @returns token
   */

  crearToken(usuario: Usuario): string{
    let datos= {
      name: `${usuario.primerNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido}`,
      role: usuario.rolId,
      email: usuario.correo
    }
    let token = jwt.sign(datos, configuracionSeguridad.claveJWT);
    return token;
  }

  /**
   * valida y obtiene el rol de un token
   * @param tk token
   * @returns el _id del rol
   */

  obtenerRolDesdeToken(tk: string):string{
    let obj = jwt.verify(tk, configuracionSeguridad.claveJWT);
    return obj.role;
  }
}
