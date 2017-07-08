//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace IppDotNetWrapper
{
    public interface IIppDotNetWrapper
    {
        bool InitDiffieHellman();
        bool GetDHPublicKey(ref Byte[] gbXLE, ref Byte[] gbYLE);
        bool GetDHSharedSecret(Byte[] gaXLEstr, Byte[] gaYLEstr, ref Byte[] sharedSecret);
        bool EncryptData(Byte[] message, byte[] encKey, byte[] IV, byte[] AAD, int encMessageLength, ref Byte[] encMessage, ref Byte[] Tag);
        bool DecryptData(Byte[] message, byte[] encKey, byte[] IV, byte[] AAD, int encMessageLength, ref Byte[] encMessage, ref Byte[] Tag);
        bool VerifySignature(byte[] bytesToVerify, byte[] signature, byte[] Mod, byte[] Exp);
    }

    public class ippApiWrapper : IIppDotNetWrapper
    {
        #region Vars
        private const int KeyDataLen = 128;
        private const int DHPublicHalfLen = 32;
        private const int DHSecretLen = 32;
        private const int DHPrivKeyLen = 32;
        private const int KeyLen = 32;
        private const int DHSighalfLen = 32;
        private const int AESKeyLen = 16;
        private const int AESSGCMTagLen = 16;
        private const int KeyBuffLen = 16;
        private const int TagBuffLen = 16;
        private const int ExpBuffLen = 4;
        #endregion

        #region P-Invokes
        [DllImport("IppWrapper.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ippWrapperInitDiffieHellman")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool ippWrapperInitDiffieHellman();

        [DllImport("IppWrapper.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ippWrapperGetDHPublicKey")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool ippWrapperGetDHPublicKey(IntPtr gbXptr, IntPtr gbYptr, ref Int32 gbLen);

        [DllImport("IppWrapper.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ippWrapperGetDHSharedSecret")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool ippWrapperGetDHSharedSecret(IntPtr gaXLE, IntPtr gaYLE, IntPtr sharedPtr, ref Int32 sharedLen);

        [DllImport("IppWrapper.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ippWrapperEncryptData")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern Boolean ippWrapperEncryptData(IntPtr message, IntPtr encKey,
            Int32 IVLen, IntPtr IV, Int32 AADLen, IntPtr AAD, Int32 MsgBufLen, IntPtr MsgBuf, IntPtr Tag);

        [DllImport("IppWrapper.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ippWrapperDecryptData")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern Boolean ippWrapperDecryptData(IntPtr message, IntPtr encKey,
            Int32 IVLen, IntPtr IV, Int32 AADLen, IntPtr AAD, Int32 MsgBufLen, IntPtr MsgBuf, IntPtr Tag);

        [DllImport("IppWrapper.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "ippWrapperVerifySignature")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern Boolean ippWrapperVerifySignature(IntPtr msg, Int32 msgLen, IntPtr sig, Int32 sigLen, IntPtr Mod, 
            Int32 ModLen, IntPtr Exp, Int32 ExpLen);

        #endregion

        public bool InitDiffieHellman()
        {
            bool result = false;
            try
            {
                result = ippWrapperInitDiffieHellman();
            }
            catch (Exception e)
            {
                Console.WriteLine("ippWrapperInitDiffieHellman exception: {0}", e.Message);
                result = false;
            }

            return result;
        }


        public bool GetDHPublicKey(ref Byte[] gbXLE, ref Byte[] gbYLE)
        {
            bool result = false;
            Int32 gblen = RaSpRef.Constants.GaGbLen;

            try
            {
                if (gbXLE == null)
                {
                    throw new System.ArgumentNullException("gbXLE");
                }
                if (gbYLE == null)
                {
                    throw new System.ArgumentNullException("gbYLE");
                }

                IntPtr gbXptr = Marshal.AllocHGlobal(DHPublicHalfLen);
                IntPtr gbYptr = Marshal.AllocHGlobal(DHPublicHalfLen);

                try
                {
                    result = ippWrapperGetDHPublicKey(gbXptr, gbYptr, ref gblen);
                }
                catch (Exception e)
                {
                    Console.WriteLine("ippWrapperGetDHPublicKey exception: {0}", e.Message);
                    result = false;
                }

                if (result)
                {
                    Marshal.Copy(gbXptr, gbXLE, 0, gblen);
                    Marshal.Copy(gbYptr, gbYLE, 0, gblen);
                }

                Marshal.FreeHGlobal(gbXptr);
                Marshal.FreeHGlobal(gbYptr);
            }
            catch (Exception e)
            {
                Console.WriteLine("GetDHPublicKey exception: {0}", e.Message);
                result = false;
            }
            return result;
        }

        Int32 secretLen;

        public bool GetDHSharedSecret(Byte[] gaXLE, Byte[] gaYLE, ref Byte[] sharedSecret)
        {
            bool result = false;

            try
            {
                if (gaXLE == null)
                {
                    throw new System.ArgumentNullException("gaXLE");
                }
                if (gaYLE == null)
                {
                    throw new System.ArgumentNullException("gaYLE");
                }
                if (sharedSecret == null)
                {
                    throw new System.ArgumentNullException("sharedSecret");
                }

                IntPtr gaXptr = Marshal.AllocHGlobal(DHPublicHalfLen);
                IntPtr gaYptr = Marshal.AllocHGlobal(DHPublicHalfLen);
                IntPtr secretPtr = Marshal.AllocHGlobal(DHSecretLen);

                Marshal.Copy(gaXLE, 0, gaXptr, DHPublicHalfLen);
                Marshal.Copy(gaYLE, 0, gaYptr, DHPublicHalfLen);

                try
                {
                    result = ippWrapperGetDHSharedSecret(gaXptr, gaYptr, secretPtr, ref secretLen);
                }
                catch (Exception e)
                {
                    Console.WriteLine("ippWrapperGetDHSharedSecret exception: {0}", e.Message);
                    result = false;
                }

                if (result)
                {
                    Marshal.Copy(secretPtr, sharedSecret, 0, DHSecretLen);
                }

                Marshal.FreeHGlobal(gaXptr);
                Marshal.FreeHGlobal(gaYptr);
                Marshal.FreeHGlobal(secretPtr);
            }
            catch (Exception e)
            {
                Console.WriteLine("GetDHSharedSecret exception: {0}", e.Message);
                result = false;
            }

            return result;
        }        

        public bool EncryptData(byte[] message, byte[] encKey, byte[] IV, byte[] AAD, int encMessageLength, ref byte[] encMessage, ref byte[] Tag)
        {
            bool result = false;
            int AADLen = 0;

            if (encMessageLength <= 0)
                return false;

            try
            {
                if (message == null)
                {
                    throw new System.ArgumentNullException("message");
                }
                if (encKey == null)
                {
                    throw new System.ArgumentNullException("encKey");
                }
                if (IV == null)
                {
                    throw new System.ArgumentNullException("IV");
                }
                if (encMessage == null)
                {
                    throw new System.ArgumentNullException("encMessage");
                }
                if (Tag == null)
                {
                    throw new System.ArgumentNullException("Tag");
                }

                IntPtr MsgBuffer = Marshal.AllocHGlobal(encMessageLength);
                IntPtr KeyBuffer = Marshal.AllocHGlobal(KeyBuffLen);
                IntPtr IvBuffer = Marshal.AllocHGlobal(IV.Length);
                IntPtr EncBuffer = Marshal.AllocHGlobal(encMessageLength);
                IntPtr TagBuffer = Marshal.AllocHGlobal(TagBuffLen);
                IntPtr AadBuffer = IntPtr.Zero;

                Marshal.Copy(message, 0, MsgBuffer, encMessageLength);
                Marshal.Copy(encKey, 0, KeyBuffer, KeyBuffLen);
                Marshal.Copy(IV, 0, IvBuffer, IV.Length);
                if (AAD != null)
                {
                    AadBuffer = Marshal.AllocHGlobal(AAD.Length);
                    Marshal.Copy(AAD, 0, AadBuffer, AAD.Length);
                    AADLen = AAD.Length;
                }
                try
                {
                    result = ippWrapperEncryptData(MsgBuffer,
                                                            KeyBuffer,
                                                            IV.Length,
                                                            IvBuffer,
                                                            AADLen,
                                                            AadBuffer,
                                                            encMessageLength,
                                                            EncBuffer,
                                                            TagBuffer);
                }
                catch (Exception e)
                {
                    Console.WriteLine("ippWrapperEncryptData exception: {0}", e.Message);
                    result = false;
                }

                if (result && MsgBuffer != IntPtr.Zero)
                {
                   Marshal.Copy(EncBuffer, encMessage, 0, encMessageLength);
                    Marshal.Copy(TagBuffer, Tag, 0, Tag.Length);
                }

                Marshal.FreeHGlobal(MsgBuffer);
                Marshal.FreeHGlobal(KeyBuffer);
                Marshal.FreeHGlobal(IvBuffer);
                Marshal.FreeHGlobal(AadBuffer);
                Marshal.FreeHGlobal(EncBuffer);
                Marshal.FreeHGlobal(TagBuffer);
            }
            catch (Exception e)
            {
                Console.WriteLine("EncryptData exception: {0}", e.Message);
                result = false;
            }

            return result;
        }

        public bool DecryptData(byte[] message, byte[] encKey, byte[] IV, byte[] AAD, int cryptMessageLength, ref byte[] dCryptMessage, ref byte[] Tag)
        {
            bool result = false;
            int AADLen = 0;

            if (cryptMessageLength <= 0)
                return false;

            try
            {
                if (message == null)
                {
                    throw new System.ArgumentNullException("message");
                }
                if (encKey == null)
                {
                    throw new System.ArgumentNullException("encKey");
                }
                if (IV == null)
                {
                    throw new System.ArgumentNullException("IV");
                }
                if (dCryptMessage == null)
                {
                    throw new System.ArgumentNullException("dCryptMessage");
                }
                if (Tag == null)
                {
                    throw new System.ArgumentNullException("Tag");
                }

                IntPtr MsgBuffer = Marshal.AllocHGlobal(cryptMessageLength);
                IntPtr KeyBuffer = Marshal.AllocHGlobal(KeyBuffLen);
                IntPtr IvBuffer = Marshal.AllocHGlobal(IV.Length);
                IntPtr AadBuffer = IntPtr.Zero;
                IntPtr dCryptBuffer = Marshal.AllocHGlobal(cryptMessageLength);
                IntPtr TagBuffer = Marshal.AllocHGlobal(TagBuffLen);

                Marshal.Copy(message, 0, MsgBuffer, cryptMessageLength);
                Marshal.Copy(encKey, 0, KeyBuffer, KeyBuffLen);
                Marshal.Copy(IV, 0, IvBuffer, IV.Length);
                if (AAD != null)
                {
                    AadBuffer = Marshal.AllocHGlobal(AAD.Length);
                    Marshal.Copy(AAD, 0, AadBuffer, AAD.Length);
                    AADLen = AAD.Length;
                }

                try
                {
                    result = ippWrapperDecryptData(MsgBuffer,
                                                            KeyBuffer,
                                                            IV.Length,
                                                            IvBuffer,
                                                            AADLen,
                                                            AadBuffer,
                                                            cryptMessageLength,
                                                            dCryptBuffer,
                                                            TagBuffer);
                }
                catch (Exception e)
                {
                    Console.WriteLine("ippWrapperDecryptData exception: {0}", e.Message);
                    result = false;
                }

                if (result && MsgBuffer != IntPtr.Zero)
                {
                    Marshal.Copy(dCryptBuffer, dCryptMessage, 0, cryptMessageLength);
                    Marshal.Copy(TagBuffer, Tag, 0, Tag.Length);
                }

                Marshal.FreeHGlobal(MsgBuffer);
                Marshal.FreeHGlobal(KeyBuffer);
                Marshal.FreeHGlobal(IvBuffer);
                Marshal.FreeHGlobal(AadBuffer);
                Marshal.FreeHGlobal(dCryptBuffer);
                Marshal.FreeHGlobal(TagBuffer);
            }
            catch (Exception e)
            {
                Console.WriteLine("DecryptData exception: {0}", e.Message);
                result = false;
            }



            return result;

        }        

        public bool VerifySignature(byte[] msg, byte[] signature, byte[] Mod, byte[] Exp)
        {
            bool result = false;

            try
            {
                if (msg == null)
                {
                    throw new System.ArgumentNullException("msg");
                }
                if (signature == null)
                {
                    throw new System.ArgumentNullException("signature");
                }
                if (Mod == null)
                {
                    throw new System.ArgumentNullException("Mod");
                }
                if (Exp == null)
                {
                    throw new System.ArgumentNullException("Exp");
                }

                IntPtr MsgBuffer = Marshal.AllocHGlobal(msg.Length);
                IntPtr SigBuffer = Marshal.AllocHGlobal(signature.Length);
                IntPtr ModBuffer = Marshal.AllocHGlobal(Mod.Length);
                IntPtr ExpBuffer = Marshal.AllocHGlobal(ExpBuffLen);

                Marshal.Copy(msg, 0, MsgBuffer, msg.Length);
                Marshal.Copy(signature, 0, SigBuffer, signature.Length);
                Marshal.Copy(Mod, 0, ModBuffer, Mod.Length);
                Marshal.Copy(Exp, 0, ExpBuffer, Exp.Length);

                try
                {
                    result = ippWrapperVerifySignature(MsgBuffer, msg.Length, SigBuffer, signature.Length, ModBuffer, Mod.Length, ExpBuffer, Exp.Length);
                }
                catch (Exception e)
                {
                    Console.WriteLine("ippWrapperVerifySignature exception: {0}", e.Message);
                    result = false;
                }

                Marshal.FreeHGlobal(MsgBuffer);
                Marshal.FreeHGlobal(SigBuffer);
                Marshal.FreeHGlobal(ModBuffer);
                Marshal.FreeHGlobal(ExpBuffer);
            }
            catch (Exception e)
            {
                Console.WriteLine("VerifySignature exception: {0}", e.Message);
                result = false;
            }
            return result;
        }
    }
}
