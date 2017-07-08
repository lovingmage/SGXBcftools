//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using log4net;
using System.Reflection;
using SgxOptions;

namespace RaSpRef
{
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Request messages
    class GetSigRl
    {
        public UInt32 gid { get; set; }
    }
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Response messages
    class SigRevList
    {
        public string sigRl { get; set; }
    }

    class SingleOrArrayConverter<T> : JsonConverter
    {
        // create a log4net logger with the same name as the full name of this class:
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static SgxOptions.SgxOptions options = new SgxOptions.SgxOptions(Properties.Settings.Default.Properties, log);

        public override bool CanConvert(Type objectType)
        {
            return (objectType == typeof(List<T>));
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader == null)
            {
                Exception e = new System.ArgumentNullException("reader");
                options.LogThrownException(e);
                throw e;
            }
            if (serializer == null)
            {
                Exception e = new System.ArgumentNullException("serializer");
                options.LogThrownException(e);
                throw e;
            }

            JToken token = JToken.Load(reader);
            if (token.Type == JTokenType.Array)
            {
                return token.ToObject<List<T>>();
            }
            return new List<T> { token.ToObject<T>() };
        }

        public override bool CanWrite
        {
            get { return false; }
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            throw new NotImplementedException();
        }
    }

    class QuoteStatus
    {
        public readonly int tlvLength = Constants.QuoteInfo.tlvLength;  // Length of the PIB's TLV header from the IAS server -should be stripped off
        public string id { get; set; }
        public string timestamp { get; set; }
        public string isvEnclaveQuoteStatus { get; set; }
        public int revocationReason { get; set; }

        [JsonProperty("pseManifestStatus")]
        [JsonConverter(typeof(SingleOrArrayConverter<string>))]
        public List<string> pseManifestStatus { get; set; }

        public string nonce { get; set; }
        public string epidPseudonym { get; set; }
        public string platformInfoBlob { get; set; }
    }
}
