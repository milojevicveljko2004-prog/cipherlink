using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipherLink.Cryptography
{
    // Interfejs određuje zajedničke operacije
    internal interface ICipher
    {
        CipherAlgorithm Algorithm { get; }

        byte[] Encrypt(byte[] data);

        byte[] Decrypt(byte[] data);
    }
}
