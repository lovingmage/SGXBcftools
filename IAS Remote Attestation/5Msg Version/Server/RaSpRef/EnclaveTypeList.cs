//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using log4net;
using System.Reflection;
using SgxOptions;
using System.IO;

namespace RaSpRef
{

    public class Payload
    {
      
        public string Encrypt { get; set; }
        public string Clear { get; set; }

        public Payload()
        {
            Encrypt = "";
            Clear = "";
        }
 
    }

    public enum TimeUnit { seconds = 0, minutes, hours, days, months, years };

    public class EnclaveType
    {

        public string Name { get; set; }
        public short ISVSVNMinLevel { get; set; }
        public string MRENCLAVE { get; set; }
        public short ISVPRODID { get; set; }
        public int LeaseDuration { get; set; }
        public TimeUnit LeaseDurationTimeUnit { get; set; }
        public bool TrustEnclaveGroupOutOfDate { get; set; }
        public bool TrustPSEOutOfDate { get; set; }
        public bool IsProductionEnclave { get; set; }
        public string MRSIGNER { get; set; }
        public Payload Payload { get; set; }

        public EnclaveType()
        {
            Name = "";
            MRSIGNER = "";
            MRENCLAVE = "";
            ISVSVNMinLevel = 0;
            ISVPRODID = 0;
            LeaseDuration = 0;
            LeaseDurationTimeUnit = TimeUnit.seconds;
            TrustEnclaveGroupOutOfDate = false;
            TrustPSEOutOfDate = false;
            IsProductionEnclave = false;
            Payload = new Payload();
        }
    }

    public class EnclaveTypeList
    {
        public List<EnclaveType> EnclaveType { get; set; }
    }


}
