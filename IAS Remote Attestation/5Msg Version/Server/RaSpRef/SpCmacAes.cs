//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Linq;
using System.Security.Cryptography;

namespace RaSpRef
{
   class SpCmacAes
   {
      private const int keyLen = 16;
      private const int dataLen = 16;
      private const byte bit7 = 0x80;
      private const byte bit7mask = 0x7f;
      private const byte bit0 = 0x01;
      private const byte bits0127 = 0x87;


      public byte[] Value(byte[] key, byte[] data)
      {
         byte[] c = new byte[keyLen];
         byte[] k0;
         byte[] k1;
         int i;

         if (key == null)
         {
            throw new System.ArgumentNullException("key");
         }
         if (key.Length != keyLen)
         {
            throw new System.ArgumentException("key");
         }

         try
         {
            /*  NOTE:  We always need k1, but we only need k2 in about half the cases.
             *  Therefore, for performance considerations, we calculate k1 now, but we hold
             *  off the final step of calculating k2 until we hit a case where we need it.
             */
            k0 = CmacEncryptStep(key, c);
            k1 = SubKeyGen(k0);

            if (data != null && data.Length > 0)
            {
               /* This is the most common case, where our data has non-zero length.
                */
               Array.Clear(c, 0, c.Length);
               for (i = 0; i < data.Length - dataLen; i += dataLen)
               {
                   for (int k = 0; k < dataLen; k++)
                  {
                     c[k] ^= data[i + k];
                  }
                  c = CmacEncryptStep(key, c);
               }
               if (i == data.Length - dataLen)
               {
                  /* The final block is not partial (i.e. 16 bytes).
                   */
                   for (int k = 0; k < dataLen; k++)
                  {
                     c[k] ^= (byte)(data[i + k] ^ k1[k]);
                  }
                  c = CmacEncryptStep(key, c);
               }
               else
               {
                  /* The final block is a partial block (i.e. 1 to 15 bytes).
                   */
                  byte[] k2;

                  k2 = SubKeyGen(k1);
                  for (int k = 0; k < dataLen; k++)
                  {
                     if (i + k < data.Length)
                     {
                        c[k] ^= data[i + k];
                     }
                     else if (i + k == data.Length)
                     {
                        c[k] ^= bit7;
                     }
                     c[k] ^= k2[k];
                  }
                  c = CmacEncryptStep(key, c);
               }
            }
            else
            {
               /*  Special case for zero-length data.
                *  NOTE: if data == null, we also treat that as this
                *  zero-length data case.
                *  Here, we use c to store the k2 subkey for performance
                *  reasons, since we would basically just be copying it
                *  over anyway.
                */
               c = SubKeyGen(k1);
               c[0] ^= bit7;
               c = CmacEncryptStep(key, c);
            }
         }
         finally
         {
         }

         return c;
      }

      private byte[] SubKeyGen(byte[] prevKey)
      {
         byte[] newSubKey = new byte[keyLen];
         for (int i = 0; i < prevKey.Length - 1; i++)
         {
             newSubKey[i] = (byte)(((prevKey[i] & bit7mask) << 1) | ((prevKey[i + 1] >> 7) & bit0));
         }
         newSubKey[prevKey.Length - 1] = (byte)(prevKey[prevKey.Length - 1] << 1);
         if ((prevKey[0] & bit7) != 0)
         {
             newSubKey[prevKey.Length - 1] ^= bits0127;
         }
         return newSubKey;
      }

      private byte[] CmacEncryptStep(byte[] key, byte[] data)
      {
          byte[] encryptedData = new byte[keyLen];

         using (Aes ourAes = Aes.Create())
         {
            ourAes.Key = key;
            ourAes.IV = new byte[keyLen];
            ourAes.Mode = CipherMode.ECB;
            ICryptoTransform encryptor = ourAes.CreateEncryptor(ourAes.Key, ourAes.IV);
            encryptor.TransformBlock(data, 0, data.Length, encryptedData, 0);
         }
         return encryptedData;
      }

      public byte[] OurAesEncrypt(byte[] key, byte[] data)
      {
          byte[] cryptedData = new byte[keyLen];
         using (Aes ourAes = Aes.Create())
         {
            ourAes.Key = key;
            ourAes.IV = new byte[keyLen];
            ourAes.Mode = CipherMode.ECB;
            ICryptoTransform cryptor = ourAes.CreateEncryptor(ourAes.Key, ourAes.IV);
            cryptor.TransformBlock(data, 0, data.Length, cryptedData, 0);
         }
         return cryptedData;
      }
   }

}
