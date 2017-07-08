//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RaSpRef
{
    class QuoteNoPSE
    {
        // Container object for sending the Quote value to IAS
        public byte[] isvEnclaveQuote { get; set; }
        public byte[] nonce { get; set; }
    }
    class QuotePSE
    {
        // Container object for sending the Quote value to IAS
        public byte[] isvEnclaveQuote { get; set; }
        public byte[] pseManifest { get; set; }
        public byte[] nonce { get; set; }
    }
}
