using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipherLink.Cryptography
{
    internal sealed class Rc4Cipher : ICipher
    {
        // RC4 koristi niz sa 256 elemenata, pa tu veličinu čuvamo kao konstantu.
        private const int StateSize = 256;

        // Stanje nakon KSA. Ne menjamo ga tokom šifrovanja.
        // Tip byte ima vrednosti od 0 do 255, što odgovara vrednostima koje RC4 čuva u svom nizu.
        private readonly byte[] initialState;

        public CipherAlgorithm Algorithm => CipherAlgorithm.RC4;

        public Rc4Cipher(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length == 0 || key.Length > 256)
            {
                throw new ArgumentException(
                    "RC4 ključ mora imati između 1 i 256 bajtova.",
                    nameof(key));
            }

            initialState = new byte[StateSize];

            InitializeState();
            KeyScheduling(key);
        }

        private void InitializeState()
        {
            // S = [0, 1, 2, ..., 255]
            for (int i = 0; i < StateSize; i++)
            {
                initialState[i] = (byte)i;
            }
        }

        private void KeyScheduling(byte[] key)
        {
            // KSA: mešanje niza S pomoću ključa.
            int j = 0;

            for (int i = 0; i < StateSize; i++)
            {
                j = (j + initialState[i] + key[i % key.Length])
                    % StateSize;

                Swap(initialState, i, j);
            }
        }

        public byte[] Encrypt(byte[] data)
        {
            return Transform(data);
        }

        public byte[] Decrypt(byte[] data)
        {
            return Transform(data);
        }

        private byte[] Transform(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            // Svaki poziv počinje kopijom stanja nakon KSA.
            byte[] state = (byte[])initialState.Clone();
            byte[] result = new byte[data.Length];

            int i = 0;
            int j = 0;

            // PRGA: generisanje ključa toka i XOR sa podacima.
            for (int position = 0; position < data.Length; position++)
            {
                i = (i + 1) % StateSize;
                j = (j + state[i]) % StateSize;

                Swap(state, i, j);

                int t = (state[i] + state[j]) % StateSize;
                byte keyStreamByte = state[t];

                result[position] = (byte)(data[position] ^ keyStreamByte);
            }

            return result;
        }

        private static void Swap(byte[] array, int first, int second)
        {
            byte temporary = array[first];
            array[first] = array[second];
            array[second] = temporary;
        }
    }
}
