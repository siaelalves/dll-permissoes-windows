using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.IO;

namespace Segurança
{
    public class Permissões
    {
        /// <summary>
        /// Define configurações de segurança e permissões para arquivos e pastas.
        /// </summary>
        /// <param name="usuário">Especifique o nome do usuário para o qual
        /// o requerimento de segurança está sendo aplicado.</param>
        /// <param name="caminho">Especifique a pasta ou arquivo
        /// que o usuário especificado pode ter acesso.</param>
        /// <param name="direitos">Especifique que uso o usuário poderá fazer
        /// do arquivo ou pasta especificados.</param>
        public void Conceder(string usuário, string caminho,
            FileSystemRights direitos)
        {
            // Create a new DirectoryInfo object.
           DirectoryInfo Dinfo = new System.IO.DirectoryInfo(caminho);
            // Get a DirectorySecurity object that represents the  
            // current security settings.
            DirectorySecurity Dsegurança = Dinfo.GetAccessControl();            
            // Add the FileSystemAccessRule to the security settings.
            Dsegurança.AddAccessRule(new FileSystemAccessRule(usuário, direitos, AccessControlType.Allow));
            // Set the new access settings.
            Dinfo.SetAccessControl(Dsegurança);
        }
         /// <summary>
        /// Define configurações de segurança e permissões para arquivos e pastas.
        /// </summary>
        /// <param name="usuário">Especifique o nome do usuário para o qual
        /// o requerimento de segurança está sendo aplicado.</param>
        /// <param name="caminho">Especifique a pasta ou arquivo
        /// que o usuário especificado não pode ter acesso.</param>
        /// <param name="direitos">Especifique que uso o usuário poderá fazer
        /// do arquivo ou pasta especificados.</param>
        public void Negar(string usuário, string caminho,
            FileSystemRights direitos)
        {
            // Create a new DirectoryInfo object.
            DirectoryInfo Dinfo = new System.IO.DirectoryInfo(caminho);
            // Get a DirectorySecurity object that represents the  
            // current security settings.
            DirectorySecurity Dsegurança = Dinfo.GetAccessControl();
            // Add the FileSystemAccessRule to the security settings.
            Dsegurança.AddAccessRule(new FileSystemAccessRule(usuário, direitos, AccessControlType.Deny));
            // Set the new access settings.
            Dinfo.SetAccessControl(Dsegurança);
        }
    }
    public class Criptografia
    {
        AesCryptoServiceProvider AESserviçoCriptografia = new AesCryptoServiceProvider();
        MD5CryptoServiceProvider MD5serviçoCriptografia = new MD5CryptoServiceProvider();
        string chave = ".Z-4hh~!V}TvB=lh8\'F";
        //
        public string Criptografar(string texto)
        {            
            byte[] hash = Encoding.Default.GetBytes(chave);
            AESserviçoCriptografia.Key = MD5serviçoCriptografia.ComputeHash(hash);
            AESserviçoCriptografia.Mode = CipherMode.ECB;
            byte[] buffer = Encoding.Default.GetBytes(texto);
            return Convert.ToBase64String(AESserviçoCriptografia.CreateEncryptor().
                TransformFinalBlock(buffer, 0, buffer.Length));
        }
        public string Descriptografar(string texto)
        {
            byte[] hash = Encoding.Default.GetBytes(chave);            
            AESserviçoCriptografia.Key = MD5serviçoCriptografia.ComputeHash(hash);
            AESserviçoCriptografia.Mode = CipherMode.ECB;
            byte[] buffer = Convert.FromBase64String(texto);            
            return Encoding.Default.GetString(AESserviçoCriptografia.CreateDecryptor().
                TransformFinalBlock(buffer, 0, buffer.Length));
        }

    }
}
