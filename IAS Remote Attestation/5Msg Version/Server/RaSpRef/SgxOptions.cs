//  Copyright (C) Intel Corporation, 2007 - 2009 All Rights Reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using log4net;
using log4net.Repository.Hierarchy;
using log4net.Core;
using log4net.Appender;
using log4net.Layout;

namespace SgxOptions
{
   /*  This class handles command line parsing and cofiguring the log4net logger.
    *
    *  Our command line option parsing assumes log4net is to be configured via
    *  config file(s) such as this:  log4net.Config.XmlConfigurator.Configure();
    *  and with the following attributes:
    *    - The root logger has at least one FileAppender (or one of its derivatives such as
    *      RollingFileAppender).
    *    - The root logger has at least one of ConsoleAppender, ColoredConsoleAppender, or
    *      ManagedColoredConsoleAppender.
    *    - If it is desired to, by default, output to just one Appender, then the threshold
    *      attribute can be used to disable other Appender(s).
    *  Here is an example of such a log4net.config:
    *      <log4net>
    *        <appender name="OurRollingFileAppender" type="log4net.Appender.RollingFileAppender">
    *          <threshold value="ALL" />  <!-- optional, forces this Appender on by default -->
    *          . . .
    *        </appender>
    *        <appender name="OurConsoleAppender" type="log4net.Appender.ConsoleAppender">
    *          <threshold value="OFF" />  <!-- optional, forces this Appender off by default -->
    *          . . .
    *        </appender>
    *        <root>
    *          <level value="WARN" />
    *          <appender-ref ref="OurRollingFileAppender" /> <!-- required, or another "file" like Appender -->
    *          <appender-ref ref="OurConsoleAppender" />     <!-- required, or another "console" like Appender -->
    *        </root>
    *      </log4net>
    *  The above example illustrates that the root logger (<root>) has one of each of the two
    *  classes of Appenders that are required. In this example, we decided to turn on the
    *  RollingFileAppender by default (log level WARN) but not the ConsoleAppender.  We managed
    *  this by the <threshold> attribute we assigned to these appenders.
    *
    *  We assume the following are in your project Properties->Settings (Properties.Settings.Default):
    *    - LoggingEnabled           bool  Application: default value for -l command line option
    *    - LoggingExceptionDetails  bool  Application: default value for -lxd command line option
    *
    *  Typically, the application subclasses from this to provide applcation specific options.
    *
    *      //============================================================================
    *      // .... inside your main application class ....
    *      //============================================================================
    *
    *      // log4net: initialize logger for our class:
    *      private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
    *
    *      // main program:
    *      // Note: command line options are optional. If you do not have any and do not want
    *      //       SgxOptions to parse any logging related options, then just leave args out.
    *      static void Main(string[] args)
    *      {
    *         var options = new MyApplicationOptions(log, args);
    *
    *         // For all of the options.Log*Exception(e)'s, the default log4net.ILog used for the log
    *         // is from the SgxOptions class constructor. You can override this by passing a
    *         // different log4net.ILog as a second parameter. For example: options.Log*Exception(e,myLog).
    *
    *         try
    *         {
    *            log.Info("application starting");  // log4net
    *            try
    *            {
    *               // Here is where the application's main code is for the body of the Main() function.
    *               // The code that goes here is completely defined by the application as it is
    *               // performing the tasks that the application is intended to do.
    *               //
    *               // At some point(s) in this code, we might decide to check some conditions for
    *               // an error of which we want to throw some kind of exception. The application
    *               // can use options.LogThrownException(.) to log that it is throwing an exception
    *               // here. For example:
    *               if (<something bad happened>)
    *               {
    *                  System.Exception e = new System.Exception("I am throwing this exception myself.");
    *                  options.LogThrownException(e);
    *                  throw e;
    *               }
    *            }
    *            catch( <some exception that we handle and do not consider to be an error> e)
    *            {
    *               options.LogCaughtException(e);
    *               <code to recover from exception and resolve here>;
    *            }
    *            catch( <some exception that we handle but consider to be an error> e)
    *            {
    *               options.LogCaughtErrorException(e);
    *               <code to recover from exception and report the error here>;
    *            }
    *         }
    *         catch (System.Exception e)
    *         {
    *            Console.WriteLine("Something bad happened that we don't handle.");
    *            options.LogUnhandledException(e);
    *            throw;
    *         }
    *         finally
    *         {
    *            log.Info("application ending");  // log4net
    *         }
    *      }
    *
    *      //============================================================================
    *      // .... sample implementation of MyApplicationOptions class ....
    *      //
    *      // Note: If you have no application specific things to add to this class,
    *      //       you can just use SgxOptions directly without defining this other
    *      //       class.
    *      //============================================================================
    *
    *      public class MyApplicationOptions: SgxOptions
    *      {
    *         public bool myOption = false;  // an application specific parameter
    *         private bool myOptionAlreadySet = false;  // used to detect duplicate settings
    *
    *         // Constructor: called typically at beginning of Main()
    *         public MyApplicationOptions(log4net.ILog callersLog, string[] args = null)
    *            : base(callersLog, args)
    *         {
    *            // Note: command line parsing (of args) already happened in base(...) above.
    *         }
    *
    *         // Optional: override the program banner if you do not like the default one:
    *         public override void PrintBanner()
    *         {
    *            if (!bannerAlreadyPrinted)
    *            {
    *               Console.WriteLine("My Application");
    *               Console.WriteLine("My copyright message.");
    *               Console.WriteLine("Additional program information as appropriate.");
    *            }
    *         }
    *
    *         // Optional: add our command line options to those printed by SgxOptions:
    *         protected override void PrintApplicationSpecificOptions()
    *         {
    *            Console.WriteLine("  -myoption [true|false]");
    *            Console.WriteLine("     Set my option. Available sub-options:");
    *            Console.WriteLine("       true  - set my option to true");
    *            Console.WriteLine("       false - set my option to false");
    *            Console.WriteLine("     current setting: {0}", (myOption?"true":"false"));
    *         }
    *
    *         // Optional: if we have our own options, parse them here:
    *         protected override void ParseApplicationSpecificOptions( string[] args,
    *                                                                  ref int i, // index into args
    *                                                                  bool mainPass ) // running the main pass?
    *         {
    *            // throw SgxOptionsException* exceptions as appropriate for command line parsing errors:
    *            //    - SgxOptionsExceptionDuplicate             - duplicate option detected
    *            //    - SgxOptionsExceptionUnrecognizedOption    - unrecognised option
    *            //    - SgxOptionsExceptionUnrecognizedSubOption - unrecognised sub-option
    *            //    - SgxOptionsExceptionMissingSubOption      - missing sub-option
    *            //    - SgxOptionsException                      - anything not covered by the others
    *            if (args[i] == "-my-option")
    *            {
    *               // we need to increment i because we have a sub-option:
    *               if (++i >= args.Length)
    *               {
    *                  throw new SgxOptionsExceptionMissingSubOption("-my-option");
    *               }
    *               if (mainPass)
    *               {
    *                  if(myOptionAlreadySet)
    *                  {
    *                     throw new SgxOptionsExceptionDuplicate("-my-option");
    *                  }
    *                  switch(args[i])
    *                  {
    *                     case "true":
    *                        myOption = true;
    *                        break;
    *                     case "false":
    *                        myOption = false;
    *                        break;
    *                     default:
    *                        throw new SgxOptionsExceptionUnrecognizedSubOption("-my-option", args[i]);
    *                        break;
    *                  }
    *                  myOptionAlreadySet = true;
    *               }
    *            }
    *            // add other options as needed:
    *            // else if (args[i] == "-my-other-option")
    *            // {
    *            // }
    *            else
    *            {
    *               throw new SgxOptionsExceptionUnrecognizedOption(args[i]);
    *            }
    *         }
    *
    *         // Optional: add any application info to the log file header here:
    *         // Note:SgxOptions takes care of all the common header stuff, such as:
    *         //    - application name, version, copyright, .NET version, etc.
    *         //    - Properties.Settings.Default.* settings and corresponding values
    *         // Whatever you add here will create additional parameter lines in
    *         // log4net.Util.PatternString %pattern{HeaderParameters}.
    *         protected override void AddApplicationSpecificLoggerParameters()
    *         {
    *            AddLoggerParameter("Here is a line of application-specific parameters.");
    *            AddLoggerParameter("Here is another line of application-specific parameters.");
    *         }
    *      }
    */
   public class SgxOptions
   {
      /*  This enum is to characterize classes of log4net Appenders that we know about.
       *  It is used when parsing the -llc and -llf options, to distinguish them.
       */
      enum LogOutputTypes { console, file };

      /*  We only do command line option parsing and log4net configuration in the first
       *  instance of this class that is created.  All others copy the state of the
       *  first, except for the log4net.ILog in the constructor.
       *  This variable lets us determine if we are the first instance, and if not, to
       *  retrieve that first instance.
       */
      protected static Object rootInstance = null;

      /*  Our default log4net.ILog for outputting log events.
       *  (e.g. with this.Log*Exception() members).
       */
      public readonly log4net.ILog log;

      /*  An indicator of whether log4net logging is enabled.
       *  Note that this is not associated with the log level. That is, if the log level
       *  for the logger is set to "OFF", we still can have logging enabled, but just
       *  not actually logging events (and log4net will still create a log file in that
       *  case, even if the logger log level is set to OFF and the FileAppender threshold
       *  is set to OFF, but it will be 0-length). However, if we set logging off, either
       *  by the -l off command line option, or default from
       *  Properties.Settings.Default.LoggingEnabled, then log4net is completely disabled
       *  and will not create the log file.
       */
      public bool logging { get; private set; }

      /*  An indicator of whether or not an invalid command line option was found.
       *  The application might want to check this to decide if it should just exit
       *  without performing its main operations.
       */
      public bool invalidOption { get; private set; }

      /*  An indicator of whether or not we include exception details in the log report
       *  of exceptions. This is set by the -lxd command line option, or defaults to
       *  Properties.Settings.Default.LoggingExceptionDetails.
       */
      public bool loggingExceptionDetails { get; private set; }

      /*  The following collection stores various product parameters that we
       *  retrieve from the environment.  We use productParametersNotRetrievedYet
       *  to tell RetrieveProductParameters() whether or not we already have them
       *  (so it can avoid retrieving them repeatedly).
       */
      private bool productParametersNotRetrievedYet = true;
      private string productVersion = "";
      private string productSimpleName = "";
      private string productName = "";
      private string productCopyright = "";
      private string productFramework = "";

      /*  The following options keep track of whether or not we already printed
       *  certain things on the System.Console, so we do not print them again.
       */
      protected bool bannerAlreadyPrinted = false;
      private bool optionsAlreadyPrinted = false;

      /*  The following keep track of whether or not certain command line
       *  options were already seen on the command line, so we can check
       *  for duplicates.
       */
      private bool loggingAlreadySpecified = false;
      private bool loggingExceptionDetailsAlreadySpecified = false;
      private bool logLevelConsoleAlreadySpecified = false;
      private bool logLevelFileAlreadySpecified = false;
      private bool logFileNameAlreadySpecified = false;

      /*  The following keep track of values for adding to the log file header.
       *  We have to collect these values during the first pass, because they
       *  are needed when configuring the logger.
       */
      private bool loggingExceptionDetailsOption = false;
      private bool loggingExceptionDetailsOptionSpecified = false;
      private string logLevelConsoleOption = null;
      private string logLevelFileOption = null;
      private string logFileNameOption = null;

      /*  Here we keep track of whether or not ConfigureLogger was already done.
       */
      private bool loggingAlreadyConfigured = false;

      /*  Here we build our application parameters for the log header section.
       */
      private string loggerParameters = "";

      /*  Here we keep the command line arguments, from the constructor, for
       *  later parsing.
       */
      private string[] args = null;

      /*  Here we keep the program command line options all flattened out
       *  for future use, as needed.
       */
      private string argList = "";

      /*  Here we store our Properties.Settings.Default.Properties that we
       *  receive from the calling application.
       */
      protected System.Configuration.SettingsPropertyCollection properties = null;

      /*  Class Constructor.
       *
       *  This constructor will parse the command line options and
       *  configure the log4net logger. This means that for subclasses,
       *  they are constructed after these things have already happened.
       *
       *  If an error occurred while parsing command line options, then:
       *    - this.invalidOption == true
       *    - this.PrintBanner() has been called.
       *    - The list of command line options and usage has been printed.
       *    - log4net has not been configured.
       *
       *  Therefore, the application should test invalidOption to decide
       *  whether it wants to proceed with normal operation, or just exit.
       *
       *  IN:
       *      callersArg:  log4net.Ilog that should be used as the default
       *          for all logging operations by this class.
       *
       *      args:  command line options from Main(string[] args). If the
       *          application does not want SgxOptions to parse command
       *          line options, then this parameter can be omitted.
       */
      public SgxOptions( System.Configuration.SettingsPropertyCollection applicationProperties,
                            log4net.ILog callersLog,
                            string[] incomingArgs = null )
      {
         log = callersLog;
         properties = applicationProperties;

         if (rootInstance == null)
         {
            /*  We are constructing the first instance of this class. Here we do the main
             *  work, such as parsing command line options and configuring log4net.
             */
            rootInstance = this;

            logging = bool.Parse(properties["LoggingEnabled"].DefaultValue.ToString());  // log4net is enabled/configured
            invalidOption = false;  // an error occurred while parsing command line options
            loggingExceptionDetails = bool.Parse(properties["loggingExceptionDetails"].DefaultValue.ToString());  // include exception details in log
            logFileNameOption = properties["LogFileName"].DefaultValue.ToString();

            args = incomingArgs;
            if (args != null)
            {
               argList = String.Join(" ", args);
            }
         }
         else
         {
            /*  We are constructing a subsequent instance of this class. The first one
             *  is at rootInstance. We skip most of the work above and just copy some
             *  parameters over.
             *
             *  All subsequence instances keep the same log4net configuration, but they
             *  have their own log4net.ILog, so everything else is copied from the
             *  rootInstance.
             */
            properties = ((SgxOptions)rootInstance).properties;
            logging = ((SgxOptions)rootInstance).logging;
            invalidOption = ((SgxOptions)rootInstance).invalidOption;
            loggingExceptionDetails = ((SgxOptions)rootInstance).loggingExceptionDetails;
            logFileNameOption = ((SgxOptions)rootInstance).logFileNameOption;
            loggingAlreadyConfigured = ((SgxOptions)rootInstance).loggingAlreadyConfigured;

            /*  We want to disable PrintBanner() from this class because then we do not
             *  have to deal with getting access to various private members of the root
             *  instance.
             */
            bannerAlreadyPrinted = true;   // disable PrintBanner() from this instance
         }
      }

      /*  virtual method: PrintBanner()
       *
       *  The default method for printing the application's banner.
       *
       *  The application can override this method via the subclass if it does not
       *  like the default banner. If it does, it should retain the checking and
       *  setting of bannerAlreadyPrinted to protect against it getting printed
       *  multiple times.
       */
      public virtual void PrintBanner()
      {
         if (!bannerAlreadyPrinted)
         {
            RetrieveProductParameters();
            Console.WriteLine("{0} ({1}) version {2}", productName, productSimpleName, productVersion);
            Console.WriteLine("{0}", productCopyright);
            bannerAlreadyPrinted = true;
         }
      }

      /*  public method: PrintOptions()
       *
       *  Prints the application's command line options and usage.
       *
       *  The virtual method, PrintApplicationSpecificOptions(), is used to include
       *  any application specific options. If the application has any such options,
       *  it should override PrintApplicationSpecificOptions() to print them.
       */
      public void PrintOptions()
      {
         if (!optionsAlreadyPrinted)
         {
            optionsAlreadyPrinted = true;
            PrintBanner();
            Console.WriteLine("  -l <on|off>: enable/disable logging functions:");
            Console.WriteLine("     If disabled, then options -lxd, -llc, -llf cannot be used.");
            Console.WriteLine("        on    - enable logging functions");
            Console.WriteLine("        off   - disable logging functions");
            Console.WriteLine("     current setting: {0}", (logging ? "on" : "off"));
            Console.WriteLine("     The default is from application settings: LoggingEnabled.");
            Console.WriteLine("  -lxd <on|off> : include exception details:");
            Console.WriteLine("     For exceptions, include detailed exception information.");
            Console.WriteLine("        on    - enable logging exception details");
            Console.WriteLine("        off   - disable logging exception details");
            Console.WriteLine("     current setting: {0}", (loggingExceptionDetails ? "on" : "off"));
            Console.WriteLine("     The default is from application settings: LoggingExceptionDetails.");
            Console.WriteLine("  -llc <log level> : set log level threshold for console:");
            Console.WriteLine("     This option overrides settings from the log4net config file.");
            Console.WriteLine("     Each level includes logging of lower levels.");
            Console.WriteLine("     (i.e. warn also includes error and fatal).");
            Console.WriteLine("        all   - enable all logging");
            Console.WriteLine("        debug - debug messages");
            Console.WriteLine("        info  - informational messages");
            Console.WriteLine("        warn  - warnings");
            Console.WriteLine("        error - general errors");
            Console.WriteLine("        fatal - fatal errors");
            Console.WriteLine("        off   - disable all logging");
            Console.WriteLine("     The default is from the log4net configuration.");
            Console.WriteLine("  -llf <log level> : set log level threshold for file:");
            Console.WriteLine("     This option overrides settings from the log4net config file.");
            Console.WriteLine("     (<log level> options are the same as for -llc)");
            Console.WriteLine("        Note: if -llf off, the log file will still be created.");
            Console.WriteLine("        but with 0 length. To avoid creating the log file, use -l off or");
            Console.WriteLine("        remove the FileAppender from <root> of log4net.config.");
            Console.WriteLine("     The default is from the log4net configuration.");
            Console.WriteLine("  -lfn <file name> : set file name for file logging:");
            Console.WriteLine("     current setting: {0}", logFileNameOption);
            Console.WriteLine("     The default is from application settings: LogFileName.");
            PrintApplicationSpecificOptions();
         }
      }

      /*  protected method: PrintApplicationSpecificOptions()
       *
       *  If the application has any command line options of its own, parsed
       *  by ParseApplicationSpecificOptions(...), then it should override this
       *  method to print usage details for these command line options.
       */
      protected virtual void PrintApplicationSpecificOptions()
      {
      }

      /*  public method: ParseOptions()
       *
       *  Parse command line options. This must be called after the class constructor.
       *
       *  If the application has any command line options of its own, it should
       *  override ParseApplicationSpecificOptions(...) so we can parse those
       *  also.
       *
       *  IN:
       *      mainPass:  indicates if this is the main parsing pass. Command line
       *          argument parsing is done in two passes. The first pass has
       *          mainPass==false and is done before configuring log4net. Actual
       *          parsing of the option should only happen when mainPass==true.
       *          In either case, i must be incremented as needed to the end of
       *          the list of sub-options.
       */
      public void ParseOptions()
      {
         try
         {
            loggingExceptionDetailsOption = loggingExceptionDetails;
            loggingExceptionDetailsOptionSpecified = false;
            logLevelConsoleOption = null;
            logLevelFileOption = null;
            ParseOptionsPass(false);  // scan the options to search for the -ll option
            ConfigureLogger();        // configure log4net (unless -ll off) based on its configuration file
            ParseOptionsPass(true);   // parse all the other options (other than -ll)
         }
         catch (SgxOptionsException e)
         {
            /*  All parsing errors come here.
             */
            PrintBanner();
            Console.WriteLine("Command Line Error: {0}", e.Message);
            invalidOption = true;
         }

         if (invalidOption)
         {
            PrintOptions();
         }
      }

      /*  private method: ParseOptionsPass(.)
       *
       *  Parse command line options. This is called by ParseOptions().
       *
       *  If the application has any command line options of its own, it should
       *  override ParseApplicationSpecificOptions(...) so we can parse those
       *  also.
       *
       *  IN:
       *      mainPass:  indicates if this is the main parsing pass. Command line
       *          argument parsing is done in two passes. The first pass has
       *          mainPass==false and is done before configuring log4net. Actual
       *          parsing of the option should only happen when mainPass==true.
       *          In either case, i must be incremented as needed to the end of
       *          the list of sub-options.
       */
      private void ParseOptionsPass( bool mainPass )
      {
         if (args != null)
         {
            for (int i = 0; i < args.Length; i++)
            {
               if (args[i] == "-l")
               {
                  if (++i >= args.Length)
                  {
                     throw new SgxOptionsExceptionMissingSubOption("-l");
                  }
                  if (!mainPass)
                  {
                     if (loggingAlreadySpecified)
                     {
                        throw new SgxOptionsExceptionDuplicate("-l");
                     }
                     switch (args[i])
                     {
                        case "on":
                           logging = true;
                           break;
                        case "off":
                           logging = false;
                           break;
                        default:
                           throw new SgxOptionsExceptionUnrecognizedSubOption("-l", args[i]);
                     }
                     loggingAlreadySpecified = true;
                  }
               }
               else if (args[i] == "-lxd")
               {
                  if (++i >= args.Length)
                  {
                     throw new SgxOptionsExceptionMissingSubOption("-lxd");
                  }
                  if (mainPass)
                  {
                     if (loggingExceptionDetailsAlreadySpecified)
                     {
                        throw new SgxOptionsExceptionDuplicate("-lxd");
                     }
                     if (!logging)
                     {
                        throw new SgxOptionsExceptionLoggingDisabled("-lxd");
                     }
                     switch (args[i])
                     {
                        case "on":
                           loggingExceptionDetails = true;
                           break;
                        case "off":
                           loggingExceptionDetails = false;
                           break;
                        default:
                           throw new SgxOptionsExceptionUnrecognizedSubOption("-l", args[i]);
                     }
                     loggingExceptionDetailsAlreadySpecified = true;
                  }
                  else
                  {
                     loggingExceptionDetailsOptionSpecified = true;
                     switch (args[i])
                     {
                        case "on":
                           loggingExceptionDetailsOption = true;
                           break;
                        case "off":
                           loggingExceptionDetailsOption = false;
                           break;
                        default:
                           break;
                     }
                  }
               }
               else if (ParseLogLevelOption( args,
                                             ref i,
                                             mainPass,
                                             "-llc",
                                             LogOutputTypes.console,
                                             ref logLevelConsoleAlreadySpecified,
                                             ref logLevelConsoleOption ))
               {
               }
               else if (ParseLogLevelOption( args,
                                             ref i,
                                             mainPass,
                                             "-llf",
                                             LogOutputTypes.file,
                                             ref logLevelFileAlreadySpecified,
                                             ref logLevelFileOption ))
               {
               }
               else if (args[i] == "-lfn")
               {
                  if (++i >= args.Length)
                  {
                     throw new SgxOptionsExceptionMissingSubOption("-lfn");
                  }
                  if (!mainPass)
                  {
                     if (logFileNameAlreadySpecified)
                     {
                        throw new SgxOptionsExceptionDuplicate("-lfn");
                     }
                     logFileNameOption = args[i];
                     logFileNameAlreadySpecified = true;
                  }
               }
               else
               {
                  ParseApplicationSpecificOptions(args, ref i, mainPass);
               }
            }
         }
      }

      /*  protected method: ParseApplicationSpecificOptions(...)
       *
       *  If the application has any application-specific command line options,
       *  then it should override this method to parse them.
       *
       *  IN:
       *      myArgs:  command line options from SgxOptions constructor.
       *
       *      i:  the current index into args[] to parse.  If the parsed option
       *          takes sub-options, then this index must be incremented until
       *          it indexes the last sub-option.
       *
       *      mainPass:  indicates if this is the main parsing pass. Command line
       *          argument parsing is done in two passes. The first pass has
       *          mainPass==false and is done before configuring log4net. Actual
       *          parsing of the option should only happen when mainPass==true.
       *          In either case, i must be incremented as needed to the end of
       *          the list of sub-options.
       */
      protected virtual void ParseApplicationSpecificOptions( string[] myArgs,
                                                              ref int i,
                                                              bool mainPass )
      {
         throw new SgxOptionsExceptionUnrecognizedOption(myArgs[i]);
      }

      /*  private method: ParseLogLevelOption(.......)
       *
       *  Called by ParseOptions(..) to deal with the -llc and -llf options.
       *
       *  IN:
       *      myArgs:  command line options from SgxOptions constructor.
       *
       *      i:  the current index into myArgs[] to parse.  If the parsed option
       *          takes sub-options, then this index must be incremented until
       *          it indexes the last sub-option.
       *
       *      mainPass:  indicates if this is the main parsing pass. Command line
       *          argument parsing is done in two passes. The first pass has
       *          mainPass==false and is done before configuring log4net. Actual
       *          parsing of the option should only happen when mainPass==true.
       *          In either case, i must be incremented as needed to the end of
       *          the list of sub-options.
       *
       *      option:  the option name (either "-llc" or "-llf").
       *
       *      logOutputType:  either LogOutputType.console or LogOutputType.file
       *          that corresponds with option. This specifies what type(s) of
       *          log4net Appenders to locate in the root logger to adjust or set
       *          their threshold property.
       *
       *      optionSet: the member bool that keeps track of whether this option
       *          was already set. We update it accordingly.
       *
       *   RETURNS:  true if the option was found (advance to the next option)
       */
      private bool ParseLogLevelOption( string[] myArgs,
                                        ref int i,
                                        bool mainPass,
                                        string option,
                                        LogOutputTypes logOutputType,
                                        ref bool optionAlreadySpecified,
                                        ref string optionValue )
      {
         bool r = false;

         if (myArgs[i] == option)
         {
            r = true;

            if (++i >= myArgs.Length)
            {
               throw new SgxOptionsExceptionMissingSubOption(option);
            }
            if (mainPass)
            {
               if (optionAlreadySpecified)
               {
                  throw new SgxOptionsExceptionDuplicate(option);
               }
               if (!logging)
               {
                  throw new SgxOptionsExceptionLoggingDisabled(option);
               }
               log4net.Core.Level logLevel = ParseLogLevelName(option, myArgs[i]);
               /* Note: klocwork may issue a warning about the next line as an invalid cast
                *       ILoggerRepository to Heirarchy. This cast is done in all (several)
                *       sample code I can find that is attempting to access the root log level
                *       and no other way appears to exist. Therefore, I assume it is valid.
                *       The klocwork documentation on this warning indicates that this may
                *       cause the program to access a non-exisit class field. Therefore, we
                *       add checks to ensure that all fields are present and then ignore
                *       the klocwork warning.
                */
               var h = (log4net.Repository.Hierarchy.Hierarchy)log4net.LogManager.GetRepository();
               if (h.GetType().GetProperty("Root") == null ||
                    h.Root.GetType().GetProperty("Level") == null ||
                    h.Root.GetType().GetProperty("Appenders") == null)
               {
                  throw new SgxOptionsException(option, "internal error: unable to cast ILoggerRepository to Hierarchy");
               }
               log4net.Core.Level oldRootLevel = h.Root.Level;
               bool setOtherAppenders = false;
               if (oldRootLevel > logLevel)
               {
                  /*  The root logger level is higher than that of the threshold we are
                     *  trying to set for this Appender. Unless we do something about this,
                     *  we will not get the lower log level through to our Appender. We
                     *  will have to set the root log level lower to enable our Appender
                     *  to act up to this log level threshold. However, there may be other
                     *  Appenders out there and we want to have minimal impact on them.
                     *  What we do for them is they did not have a threshold set or if
                     *  that threshold was set lower than the old root log level, then
                     *  set its threshold to the old root log level.
                     */
                  h.Root.Level = logLevel;
                  setOtherAppenders = true;
               }
               /* Note: klocwork may issue a warning about the following foreach as an
                * invalid cast. See the comments a few lines up regarding the declaration
                * of var h.
                */
               foreach (log4net.Appender.IAppender a in h.Root.Appenders)
               {
                  if (IsLogOutputType(logOutputType, a))
                  {
                     if (a is log4net.Appender.AppenderSkeleton)
                     {
                        log4net.Appender.AppenderSkeleton s = a as log4net.Appender.AppenderSkeleton;
                        s.Threshold = logLevel;
                        optionAlreadySpecified = true;
                     }
                     else
                     {
                        throw new SgxOptionsException( option,
                                                          String.Format("{0} is not an AppenderSkeleton",
                                                                         a.GetType().ToString()));
                     }
                  }
                  else if (setOtherAppenders)
                  {
                     if (a is log4net.Appender.AppenderSkeleton)
                     {
                        log4net.Appender.AppenderSkeleton s = a as log4net.Appender.AppenderSkeleton;
                        if (s.Threshold == null || s.Threshold < oldRootLevel)
                        {
                           s.Threshold = oldRootLevel;
                        }
                     }
                  }
               }
               if (!optionAlreadySpecified)
               {
                  throw new SgxOptionsException( option,
                                                    String.Format("an appropriate Appender is not found in <root> (log4net config)"));
               }
            }
            else
            {
                optionValue = myArgs[i];
            }
         }

         return r;
      }

      /*  private method: ParseLogLevelName(.)
       *
       *  Parses a command line sub-option for a log level.
       *  Called by ParseOptions(..) to deal with the -llc and -llf options.
       *
       *  IN:
       *      option:  the command line option we are parsing ("-llc" or "-llf").
       *
       *      logLevelName:  a log level name (e.g. "all", "info", "error", etc.)
       *
       *   RETURNS:  the corresponding log4net.Core.Level
       */
      static private log4net.Core.Level ParseLogLevelName(string option, string logLevelName)
      {
         log4net.Core.Level logLevel = log4net.Core.Level.All;

         switch (logLevelName.ToLower())
         {
            case "all":
               logLevel = log4net.Core.Level.All;
               break;
            case "debug":
               logLevel = log4net.Core.Level.Debug;
               break;
            case "info":
               logLevel = log4net.Core.Level.Info;
               break;
            case "warn":
               logLevel = log4net.Core.Level.Warn;
               break;
            case "error":
               logLevel = log4net.Core.Level.Error;
               break;
            case "fatal":
               logLevel = log4net.Core.Level.Fatal;
               break;
            case "off":
               logLevel = log4net.Core.Level.Off;
               break;
            default:
               throw new SgxOptionsExceptionUnrecognizedSubOption(option, logLevelName);
         }

         return logLevel;
      }

      /*  private method: IsLogOutputType(..)
       *
       *  Checks if a given log4net.Appender.IAppender matches the provided LogOutputTypes.
       *  Called by ParseOptions(..) to check if a given appender matches the option (-llc or -llf).
       *
       *  IN:
       *      logOutputType:  the LogOutputTypes.* that we want to check against.
       *
       *      appender:  a og4net.Appender.IAppender to check
       *
       *   RETURNS:  true if the appender matches the logOutputType
       */
      static private bool IsLogOutputType( LogOutputTypes logOutputType,
                                           log4net.Appender.IAppender appender )
      {
         bool r = false;

         switch (logOutputType)
         {
            case LogOutputTypes.console:
               if ( appender is log4net.Appender.ConsoleAppender ||
                    appender is log4net.Appender.ColoredConsoleAppender ||
                    appender is log4net.Appender.ManagedColoredConsoleAppender)
               {
                  r = true;
               }
               break;
            case LogOutputTypes.file:
               if (appender is log4net.Appender.FileAppender)
               {
                  r = true;
               }
               break;
            default:
               break;
         }

         return r;
      }

      /*  private method: ConfigureLogger()
       *
       *  Configures log4net.
       *
       *  This is done after the first pass of parsing options, but before the second pass (mainPass==true).
       *  In the second parsing pass, the log4net configuration can be dynamically adjusted based on
       *  command line options.
       *
       *  Configuration first involves setting up our log4net.Util.PatternString %property{} values.
       *  We add various properties useful in the log4net header, or other places, such as information
       *  about the application or its environment.
       *
       *  Once all this is done, we call log4net.Config.XmlConfigurator.Configure() to tell log4net
       *  to go configure itself from its configuration file(s).
       */
      private void ConfigureLogger()
      {
         try
         {
            if (logging && !loggingAlreadyConfigured)
            {
               loggingAlreadyConfigured = true;
               logFileNameOption = System.IO.Path.GetFullPath(logFileNameOption);
               loggerParameters = "";
               AddLoggerParameter(String.Format( "Logging: -l {0} [from {1}]",
                                                 logging ? "on" : "off",
                                                 loggingAlreadySpecified ? "command line" :
                                                                           "application settings: LoggingEnabled"));
               AddLoggerParameter(String.Format( "Logging: -lxd {0} [from {1}]",
                                                 loggingExceptionDetailsOption ? "on" : "off",
                                                 loggingExceptionDetailsOptionSpecified ? "command line" :
                                                                                          "application settings: LoggingExceptionDetails"));
               if (logLevelFileOption != null)
               {
                  AddLoggerParameter(String.Format("Logging: -llf {0} [from command line]", logLevelFileOption));
               }
               else
               {
                  AddLoggerParameter("Logging: -llf not set [see log4net configuration file]");
               }
               if (logLevelConsoleOption != null)
               {
                  AddLoggerParameter(String.Format("Logging: -llc {0} [from command line]", logLevelConsoleOption));
               }
               else
               {
                  AddLoggerParameter("Logging: -llc not set [see log4net configuration file]");
               }
               AddLoggerParameter(String.Format( "Logging: -lfn {0} [from {1}]",
                                                 logFileNameOption,
                                                 logFileNameAlreadySpecified ? "command line" :
                                                                               "application settings: LogFileName"));
               AddApplicationSpecificLoggerParameters();
               RetrieveProductParameters();
               log4net.GlobalContext.Properties["HeaderVersion"] = productVersion;
               log4net.GlobalContext.Properties["HeaderSimpleName"] = productSimpleName;
               log4net.GlobalContext.Properties["HeaderProductName"] = productName;
               log4net.GlobalContext.Properties["HeaderCopyright"] = productCopyright;
               log4net.GlobalContext.Properties["HeaderFrameworkName"] = productFramework;
               log4net.GlobalContext.Properties["HeaderArgs"] = argList;
               log4net.GlobalContext.Properties["HeaderParameters"] = loggerParameters;
               log4net.GlobalContext.Properties["HeaderRule"] = new String('=', 70);
               log4net.GlobalContext.Properties["FooterRule"] = new String('-', 70);
               log4net.GlobalContext.Properties["LogFileName"] = logFileNameOption;
               log4net.Config.XmlConfigurator.Configure();
            }
         }
         catch (System.Exception)
         {
            throw new SgxOptionsException("a general problem occurred while configuring log4net");
         }
      }

      /*  private method: RetrieveProductParameters()
       *
       *  Retrieve a bunch of parameters from the application and/or environment.
       *  These parameters are stored in member variables, product*. They are then
       *  used in PrintBanner() to print our default banner, and also in ConfigureLogger()
       *  to set up our log4net parameters.
       */
      private void RetrieveProductParameters()
      {
         if (productParametersNotRetrievedYet)
         {
            System.Reflection.Assembly assembly = System.Reflection.Assembly.GetEntryAssembly();
            if (assembly != null)
            {
               object[] customAttributes = null;
               productVersion = assembly.GetName().Version.ToString();
               productSimpleName = assembly.GetName().Name;
               customAttributes = assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyProductAttribute), false);
               if (customAttributes != null && customAttributes.Length > 0)
               {
                  productName = ((System.Reflection.AssemblyProductAttribute)customAttributes[0]).Product;
               }
               customAttributes = assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyCopyrightAttribute), false);
               if (customAttributes != null && customAttributes.Length > 0)
               {
                  productCopyright = ((System.Reflection.AssemblyCopyrightAttribute)customAttributes[0]).Copyright;
               }
               customAttributes = assembly.GetCustomAttributes(typeof(System.Runtime.Versioning.TargetFrameworkAttribute), false);
               if (customAttributes != null && customAttributes.Length > 0)
               {
                  productFramework = ((System.Runtime.Versioning.TargetFrameworkAttribute)customAttributes[0]).FrameworkName;
               }
            }

            productParametersNotRetrievedYet = true;
         }
      }

      /*  protected method: AddApplicationSpecificLoggerParameters()
       *
       *  The default method for collecting application-specific
       *  log4net.Util.PatternString %property{HeaderArgs} parameters.
       *
       *  The application can override this method via the subclass if it has any
       *  application-specific parameters to be added. For each parameter that is
       *  added, the application creates a one line string for it and passes to
       *  AddLoggerParameter(.).  AddLoggerParameter(.) will then add them to the
       *  overall list.
       */
      protected virtual void AddApplicationSpecificLoggerParameters()
      {
      }

      /*  protected method: AddLoggerParameter()
       *
       *  Adds new lines of parameters to what ConfigureLogger() places in
       *  log4net.Util.PatternString %property{HeaderArgs}.
       *
       *  Called by ConfigureLogger() to get the standard parameters in.
       *  Also called by an application-specific override of
       *  AddApplicationSpecificLoggerParameters() to add application-specific
       *  parameters.
       */
      protected void AddLoggerParameter(string parameter = "")
      {
         if (parameter.Length > 0)
         {
            loggerParameters += "  " + parameter + Environment.NewLine;
         }
      }

      /*  public method: LogCaughtException(..)
       *
       *  Used by the application to log exceptions that it caught and that it does
       *  not consider to be errors.
       *
       *  IN:
       *      e:  the applicable System.Exception.
       *
       *      callersLog:  [optional] a log4net.ILog to use. If not provided, then
       *          the one provided to the class constructure will be used.
       */
      public void LogCaughtException(System.Exception e, log4net.ILog callersLog = null)
      {
         if (logging)
         {
            if (callersLog == null)
            {
               callersLog = log;
            }
            callersLog.Info(LogExceptionMessage(e, String.Format( "caught {0}: {1}",
                                                                  e.GetType().FullName,
                                                                  e.Message ) ));
         }
      }

      /*  public method: LogCaughtErrorException(..)
       *
       *  Used by the application to log exceptions that it caught. Unlike LogCaughtException(..)
       *  this is used for exceptions that are considered to be errors.
       *
       *  IN:
       *      e:  the applicable System.Exception.
       *
       *      callersLog:  [optional] a log4net.ILog to use. If not provided, then
       *          the one provided to the class constructure will be used.
       */
      public void LogCaughtErrorException(System.Exception e, log4net.ILog callersLog = null)
      {
         if (logging)
         {
            if (callersLog == null)
            {
               callersLog = log;
            }
            callersLog.Error(LogExceptionMessage(e, String.Format( "caught (error?) {0}: {1}",
                                                                   e.GetType().FullName,
                                                                   e.Message ) ));
         }
      }

      /*  public method: LogThrownException(..)
       *
       *  Used by the application to log exceptions that it is about to throw.
       *
       *  IN:
       *      e:  the applicable System.Exception.
       *
       *      callersLog:  [optional] a log4net.ILog to use. If not provided, then
       *          the one provided to the class constructure will be used.
       */
      public void LogThrownException(System.Exception e, log4net.ILog callersLog = null)
      {
         if (logging)
         {
            if (callersLog == null)
            {
               callersLog = log;
            }
            callersLog.Error(LogExceptionMessage(e, String.Format( "thrown {0}: {1}",
                                                                   e.GetType().FullName,
                                                                   e.Message ) ));
         }
      }

      /*  public method: LogCaughtErrorException(..)
       *
       *  Used by the application to log exceptions that it normally would not catch.
       *  These exceptions are rethrown and returned back from the application. They
       *  generally indicate a really bad thing happened, so we log them at
       *  log level fatal.
       *
       *  After calling this method, the application should rethrow the exception
       *  and not catch it anywhere else. If the application will catch it again
       *  somewhere else, then it should use LogCaughtException(..) or
       *  LogCaughtErrorException(..) instead.
       *
       *  IN:
       *      e:  the applicable System.Exception.
       *
       *      callersLog:  [optional] a log4net.ILog to use. If not provided, then
       *          the one provided to the class constructure will be used.
       */
      public void LogUnhandledException(System.Exception e, log4net.ILog callersLog = null)
      {
         if (logging)
         {
            if (callersLog == null)
            {
               callersLog = log;
            }
            callersLog.Fatal(LogExceptionMessage(e, String.Format( "unhandled {0}: {1}",
                                                                   e.GetType().FullName,
                                                                   e.Message ) ));
         }
      }

      /*  private method: LogExceptionMessage()
       *
       *  Construct the log message to be sent to log4net for a given
       *  exception. This method takes care of collecting additional
       *  exception details if we are doing that.
       *
       *  Called by Log*Exception(..).
       *
       *  IN:
       *      e:  the applicable System.Exception.
       *
       *      message:  the main (non-detailed) version of the log message.
       *
       *   RETURNS:  the full message to send to log4net
       */
      private string LogExceptionMessage(System.Exception e, String message)
      {
         string r = message;
         string exceptionDetails = "";

         if (loggingExceptionDetails)
         {
            string indentation = "  ";

            for (System.Exception ie = e;  ie != null;  ie = ie.InnerException)
            {
               if (exceptionDetails.Length > 0)
               {
                  exceptionDetails += Environment.NewLine;
               }
               exceptionDetails += string.Format( "{0}{1} ({2})",
                                                  indentation,
                                                  ie.Message,
                                                  ie.GetType().FullName );
               indentation += "  ";
            }
         }

         if (exceptionDetails.Length > 0)
         {
            if (r.Length > 0)
            {
               r += Environment.NewLine;
            }
            r += exceptionDetails;
         }

         return r;
      }
   }

   /*  SgxOptions command line options exception: general parsing errors
    *
    *  Thrown by methods in SgxOptions and corresponding subclasses to
    *  indicate a general command line option parsing error that is not
    *  covered by any of the other SgxOptionsException* exceptions.
    *
    *  IN: 2 parameters:
    *      option:  the command line option where the parsing error occurred.
    *
    *      message:  the error message.
    *
    *  IN: 1 parameter:
    *      message:  the complete error message.
    */
   public class SgxOptionsException : System.Exception
   {
      public SgxOptionsException(string option, string message)
         : base(String.Format("invalid option: {0}: {1}", option, message))
      {

      }
      public SgxOptionsException(string message)
         : base(message)
      {

      }
   }

   /*  SgxOptions command line options exception: duplicate option
    *
    *  Thrown by methods in SgxOptions and corresponding subclasses to
    *  indicate that a command line option was found more than once.
    *
    *  IN:
    *      option:  the command line option where the parsing error occurred.
    */
   public class SgxOptionsExceptionDuplicate : SgxOptionsException
   {
      public SgxOptionsExceptionDuplicate(string option)
         : base(option, "cannot be specified more than once")
      {
      }
   }

   /*  SgxOptions command line options exception: unrecognized option
    *
    *  Thrown by methods in SgxOptions and corresponding subclasses to
    *  indicate that a command line option was found that was not recognized.
    *
    *  IN:
    *      option:  the command line option where the parsing error occurred.
    */
   public class SgxOptionsExceptionUnrecognizedOption : SgxOptionsException
   {
      public SgxOptionsExceptionUnrecognizedOption(string option)
         : base(option, "unrecognized option")
      {
      }
   }

   /*  SgxOptions command line options exception: unrecognized suboption
    *
    *  Thrown by methods in SgxOptions and corresponding subclasses to
    *  indicate that a command line option that was expecting a suboption
    *  and that suboption was not recognized.
    *
    *  IN:
    *      option:  the command line option where the parsing error occurred.
    *
    *      subOption:  the unrecognized suboption.
    */
   public class SgxOptionsExceptionUnrecognizedSubOption : SgxOptionsException
   {
      public SgxOptionsExceptionUnrecognizedSubOption(string option, string subOption)
         : base(option, String.Format("unrecognized suboption: {0}", subOption))
      {
      }
   }

   /*  SgxOptions command line options exception: missing suboption
    *
    *  Thrown by methods in SgxOptions and corresponding subclasses to
    *  indicate that a command line option that was expecting a suboption
    *  and that suboption was missing.
    *
    *  IN:
    *      option:  the command line option where the parsing error occurred.
    */
   public class SgxOptionsExceptionMissingSubOption : SgxOptionsException
   {
      public SgxOptionsExceptionMissingSubOption(string option)
         : base(option, "missing suboption")
      {
      }
   }

   /*  SgxOptions command line options exception: cannot be used when logging is disabled
    *
    *  Thrown by methods in SgxOptions and corresponding subclasses to
    *  indicate that a command line option requires logging to be enabled but
    *  logging is disabled.
    *
    *  Only throw this exception after the first command line parsing pass and
    *  and if (!logging).
    *
    *  IN:
    *      option:  the command line option where the parsing error occurred.
    */
   public class SgxOptionsExceptionLoggingDisabled : SgxOptionsException
   {
      public SgxOptionsExceptionLoggingDisabled(string option)
         : base(option, "requires logging enabled (e.g. -l on)")
      {
      }
   }
}
