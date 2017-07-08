//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RaSpRef
{
    class ClientTransaction
    {
        public SpSequenceCheck sigmaSequenceCheck = new SpSequenceCheck();
        public string ID { get; set; }

        private Thread timeoutThread = null;

        /// <summary>
        /// Create new ClientTransaction object for storing client-specific data, such as nonce
        /// </summary>
        public ClientTransaction(string ID)
        {
            if (String.IsNullOrEmpty(ID) || ID.Equals(Constants.zeroNonceSz))
            {
                // Set the ID for tracking client
                string newID = BitConverter.ToString(sigmaSequenceCheck.currentNonce);
                this.ID = newID.Replace("-", "").Trim();
            }
            else
            {
                this.ID = ID;
            }
        }

        /// <summary>
        /// Set Thread that the client uses for tracking it's timeout status
        /// </summary>
        /// <param name="t">Thread to use for tracking client timeout</param>
        public void setTimerThread(Thread t)
        {
            // Note t==null case (i.e. timeoutThread==null) is supported in the code

            timeoutThread = t;
        }

        /// <summary>
        /// Kills the timeout thread associated with the client
        /// </summary>
        public void killTimerThread()
        {
            if (timeoutThread != null && timeoutThread.IsAlive)
            {
                timeoutThread.Abort();
                timeoutThread = null;
            }
        }
    }
}
