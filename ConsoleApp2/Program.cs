using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Threading;
using Castle.MicroKernel.Registration.Interceptor;
using MCB.MasterPiece.Data.CollectionClasses;
using MCB.MasterPiece.Data.DaoClasses;
using MCB.MasterPiece.Data.EntityClasses;
using MCB.MasterPiece.Data.FactoryClasses;
using MCB.MasterPiece.Data.HelperClasses;
using MCB.MasterPiece.Site.Modules;
using MCB.MasterPiece.Site.Modules.Commerce.Customers;
using MCB.MasterPiece.Site.SiteUser;
using MCB.MasterPiece.Site.Providers.SourceProvider;
using SD.LLBLGen.Pro.ORMSupportClasses;
using SD.LLBLGen.Pro.QuerySpec;
using MCB.MasterPiece.Hashing.Enums;
using MCB.MasterPiece.Hashing.Services;
using MCB.MasterPiece.Site.Encryption;
using MCB.MasterPiece.Site.Providers.WebsiteProvider;
using SD.LLBLGen.Pro.QuerySpec.SelfServicing;



namespace PasswordHashing
{
    class Program
    {
        static void Main(string[] args)
        {
            var connectionString = "";
            // PROD CONNECTION STRING
            connectionString = MCB.Configuration.ServerConfig.GetConnectionString(5);

            // TEST CONNECTION STRING masterpiece-20180130
//            connectionString = "data source=172.22.51.41;persist security info=False;initial catalog=masterpiece-20180130;Trusted_Connection=True;Min Pool Size = 0; Max Pool Size=600";

            MCB.MasterPiece.Data.DaoClasses.CommonDaoBase.ActualConnectionString = connectionString;

            PBKDF2HashingService hashingService = new PBKDF2HashingService();

            Stopwatch stopwatch = new Stopwatch();
            Process.GetCurrentProcess().ProcessorAffinity = new IntPtr(2); // Uses the second Core or Processor for the Test
            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High;      // Prevents "Normal" processes from interrupting Threads
            Thread.CurrentThread.Priority = ThreadPriority.Highest;     // Prevents "Normal" Threads from interrupting this thread
            stopwatch.Reset();
            stopwatch.Start();
            Console.WriteLine("Password Hashing has started");

//            int filterHusetSiteGuid = 11961;
            int MCBwebbizSiteGuid = 10535;
            AdminSitesCollection adminSites = GetAdminSites(MCBwebbizSiteGuid);
            Console.WriteLine("Number of Admin Sites: " + adminSites.Count);

            IDictionary<int, string> excludeListDictionary = GetExcludeSitelist();
            Console.WriteLine("Excluding " + excludeListDictionary.Count + " sites");

            var numberOfAdminSites = adminSites.Count;
            if (numberOfAdminSites > 10)
            {
                numberOfAdminSites = 10;
            }
            if (numberOfAdminSites > 0)
            {
                Console.WriteLine("Starting site loop: "+numberOfAdminSites+ " sites");
                for (var i = 0; i < numberOfAdminSites; i++)
                {
                    int siteGuid = adminSites[i].SiteGuid;
                    if (excludeListDictionary.ContainsKey(siteGuid))
                    {
                        Console.WriteLine("-------------------------------------------------------");
                        Console.WriteLine(siteGuid + " -> NO HASHING, " + adminSites[i].AdminCompany.Name);
                    }
                    else
                    {
                        Console.WriteLine("-------------------------------------------------------");
                        Console.WriteLine(siteGuid + " -> Start Hashing, " + adminSites[i].AdminCompany.Name);
                        Console.WriteLine("Fist ensure that the site has module 21, with moduleparameter 3050 and moduleparametervalue 1");
                        var passwordPashingEnabled = EnableMuduleKartotakforSite(siteGuid);
                        if (passwordPashingEnabled)
                        {
                            Console.Write("         AmountLeft: ");
                            var siteUsers = new SiteUserCollection();
                            ISortExpression sortExpression = new SortExpression(SiteUserFields.SiteUserGuid | SortOperator.Ascending);
                            IPredicateExpression filter = GetSelectionFilter(siteGuid);
                            siteUsers.GetMulti(filter, null, null);
                            var amountLeft = siteUsers.GetDbCount(filter);
                            Console.Write(amountLeft);
                            if (amountLeft == 0)
                            {
                                Console.WriteLine(", Der var IKKE nongen at hashe");
                            }
                            else
                            {
                                while (amountLeft > 0)
                                {
                                    amountLeft -= PasswordHashing(hashingService, stopwatch, siteGuid, 30); // hashing 30 at the time. This is approx 20sec for hashing and 1sec to update the database.
                                    if (amountLeft == 0)
                                    {
                                        Console.WriteLine("         AmountLeft: " + amountLeft + ". ");
                                    }
                                    else
                                    {
                                        Console.Write("         AmountLeft: " + amountLeft);
                                    }
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine(", Password Hashing is NOT enabled for this site, and automatic enabling has failed");
                        }
                    }
                }
            }
            stopwatch.Stop();

            Console.WriteLine("Password Hashing has finished");
            Console.WriteLine("mS: " + stopwatch.ElapsedMilliseconds);
            Console.WriteLine("-------------------------------------------------------");
            Console.WriteLine("Press ENTER to close.");
            Console.ReadLine();
        }



        static int PasswordHashing(PBKDF2HashingService hashingService, Stopwatch stopwatch, int siteGuid, int batchSize)
        {

            var split1 = stopwatch.ElapsedMilliseconds;
            var siteUsers = new SiteUserCollection();
            ISortExpression sortExpression = new SortExpression(SiteUserFields.SiteUserGuid | SortOperator.Ascending);
            IPredicateExpression filter = GetSelectionFilter(siteGuid);
            siteUsers.GetMulti(filter, null, batchSize); // We retreive a max of batchSize users
            var split2 = stopwatch.ElapsedMilliseconds;

            var amt = siteUsers.GetDbCount(filter);
            var split3 = stopwatch.ElapsedMilliseconds;

            var loopsize = amt > batchSize ? batchSize : amt;
            Console.Write(", Fetching: " + loopsize + " users " + (split2 - split1) + "mS, ");

            var split4 = stopwatch.ElapsedMilliseconds;
            var clearTextPassword = "";
            var hashedPassword = "";
            var updatedSiteUsers = new SiteUserCollection();
//            for (var j = 0; j < loopsize; j++)
//            {
//                SiteUserEntity user = siteUsers[j];
            foreach (SiteUserEntity user in siteUsers)
            {
                    
                clearTextPassword = user.SiteUserPassword;
                var before = stopwatch.ElapsedMilliseconds;
                hashedPassword = hashingService.CreateHash(clearTextPassword);
                var after = stopwatch.ElapsedMilliseconds;
                Console.WriteLine("");
                Console.WriteLine(" # " + user.SiteUserGuid + " EMAIL: " + user.SiteUserEmail);
                SiteUserEntity updatedUser = new SiteUserEntity();
                updatedUser.IsNew = false;
                updatedUser.SiteUserGuid = user.SiteUserGuid;
                updatedUser.SiteUserPassword = hashedPassword;
                updatedUser.HashType = (int)HashTypeEnum.PBKDF2;
                updatedSiteUsers.Add(updatedUser);
            }
            var split5 = stopwatch.ElapsedMilliseconds;
            // The updatedSiteUsers only contains siteUserGuid, hashedPassword and hashType
            // Hence overwriting other attributes should be avoided

            updatedSiteUsers.SaveMulti();
//            Console.WriteLine("Click here to save " + updatedSiteUsers.Count + " users.... !");
//            Console.ReadLine();
            //            Thread.Sleep(2000); // TODO enable line above an remove this one , simulate the Save time....

            var split6 = stopwatch.ElapsedMilliseconds;

            Console.Write("Hashing: " + (split5 - split4) + "mS, ");
            Console.Write(loopsize > 0 ? "(" + ((split5 - split4) / loopsize) + "mS/hashing), " : ", ");
            Console.WriteLine("Saving: " + (split6 - split5) + "mS");

            return loopsize; // Hashed in this batch
        }

        static IPredicateExpression GetSelectionFilter(int siteGuid)
        {
            IPredicateExpression filter = new PredicateExpression();
            filter.Add(SiteUserFields.SiteUserPassword.IsNotNull())
                .Add(SiteUserFields.HashType.Equal(HashTypeEnum.None))
                .Add(SiteUserFields.SiteGuid == siteGuid)
                .Add(SiteUserFields.SiteUserEmail.Like("%sma%@mcb.dk%")
                    .Or(SiteUserFields.SiteUserEmail.Like("%drc@mcb.dk%")))
                //                .Add(SiteUserFields.SiteUserPassword.Like("%MCB%"))
                .Add(SiteUserFields.SiteUserPassword.NotEqual(""));
            return filter;
        }
        static AdminSitesCollection GetAdminSites(int siteGuid)
        {
            IPredicateExpression filter = new PredicateExpression();
            filter.Add(AdminSitesFields.SiteTypeGuid == 3);
            filter.Add(AdminSitesFields.AccountingMarkAsInactive == 0);
            if (siteGuid > -1)
            {
                filter.Add(AdminSitesFields.SiteGuid == siteGuid);
            }
            var adminSites = new AdminSitesCollection();
            adminSites.GetMulti(filter, null, null);

            return adminSites;
        }

        static Boolean EnableMuduleKartotakforSite(int siteGuid)
        {
             int adminSiteModuleGuid = EnableAdminSiteModule21(siteGuid);

            if (adminSiteModuleGuid>-1)
            {
                // Add site module parameter here
                int result = EnableAdminSiteModuleParameterValue3050ForModule21(adminSiteModuleGuid);
                if (result > -1)
                {
                    return true;
                } 
                return false;
            }
            return false;
        }

        static int EnableAdminSiteModule21(int siteGuid)
        {
            AdminSiteModuleCollection adminSiteModuleCollection = new AdminSiteModuleCollection();
            IPredicateExpression filter = new PredicateExpression();
            filter.Add(AdminSiteModuleFields.SiteGuid==siteGuid);
            filter.Add(AdminSiteModuleFields.ModuleGuid == 21);
            adminSiteModuleCollection.GetMulti(filter, null, null);

            if (adminSiteModuleCollection.Count == 0)
            {
                // insert admin_site_module
                AdminSiteModuleEntity adminSiteModuleEntity = new AdminSiteModuleEntity();
                adminSiteModuleEntity.SiteGuid = siteGuid;
                adminSiteModuleEntity.ModuleGuid = 21;
                adminSiteModuleEntity.ModuleModified = DateTime.Now;
                adminSiteModuleEntity.IsNew = true;
                var saveResult = adminSiteModuleEntity.Save();
                var guid = adminSiteModuleEntity.SiteModuleGuid;
                return guid;
            }
            else if (adminSiteModuleCollection.Count == 1)
            {
                // return the siteModuleGuid
                return adminSiteModuleCollection[0].SiteModuleGuid;
            }
            else
            {
                return -1;
            }
        }

        static int EnableAdminSiteModuleParameterValue3050ForModule21(int siteModuleGuid)
        {
            AdminSiteModuleParametersCollection adminSiteModuleParametersCollection = new AdminSiteModuleParametersCollection();
            IPredicateExpression filter = new PredicateExpression();
            filter.Add(AdminSiteModuleParametersFields.SiteModuleGuid  == siteModuleGuid);
            filter.Add(AdminSiteModuleParametersFields.ModuleParameterGuid== 3050);

            adminSiteModuleParametersCollection.GetMulti(filter, null, null);
            if (adminSiteModuleParametersCollection.Count == 0)
            {
                // insert admin_site_module
                AdminSiteModuleParametersEntity adminSiteModuleParameters = new AdminSiteModuleParametersEntity();
                adminSiteModuleParameters.SiteModuleGuid = siteModuleGuid;
                adminSiteModuleParameters.ModuleParameterGuid = 3050;
                adminSiteModuleParameters.SiteModuleParameterValue = "1";
                adminSiteModuleParameters.IsNew = true;
                var result = adminSiteModuleParameters.Save();
                var guid = adminSiteModuleParameters.SiteModuleGuid;
                return guid;
            }
            else if (adminSiteModuleParametersCollection.Count == 1)
            {
                // set the parameter value to "1"
                adminSiteModuleParametersCollection[0].SiteModuleParameterValue = "1";
                adminSiteModuleParametersCollection[0].Save();
                return adminSiteModuleParametersCollection[0].SiteModuleGuid;
            }
            else
            {
                return -1;
            }
        }

        // This mthod returns all the sites that dont need to have the passwords hashed
        // The list is provided by Allan Lund
        static Dictionary<int, string> GetExcludeSitelist()
        {
            Dictionary<int, string> returnList = new Dictionary<int, string>()
            {
                {10485, "Special Butikken"},
                {10620, "vildmedvin.dk"},
                {10649, "SpejderSport.dk"},
                {10716, "jyskkemi.dk"},
                {11108, "linds.dk"},
                {11402, "BIKE&CO"},
                {11585, "HHC Distribution"},
                {11615, "Georg Jensen Damask"},
                {11659, "LD Handel & Miljø A/S"},
                {11677, "Kirstine Hardam"},
                {11708, "Danzafe A/S"},
                {11711, "Kalu A/S"},
                {11717, "Solid Shop"},
                {11723, "GACELL A/S"},
                {11731, "Antalis Packaging webshop"},
                {11746, "Humoer.dk"},
                {11750, "Alfa Travel 2012"},
                {11795, "OiSoiOi"},
                {11829, "Staby fliser og hegn"},
                {11870, "Lampemesteren.dk"},
                {11978, "Danfilter"},
                {11981, "Alere A/S (2015)"},
                {12031, "Performance Group Scandinavia A/S"},
                {12046, "UCHolstebro.dk - Intranet"},
                {12093, "Alere A/S SE (2015)"},
                {12094, "Alere A/S NO (2015)"},
                {12134, "WOUD A/S"},
                {12160, "Wiley X 2015"},
                {12201, "HELMUTH A. JENSEN A/S"},
                {12221, "Indura"},
                {12239, "BON'A PARTE"},
                {12256, "Aarhus Isenkram"},
                {12279, "ROYKON AS"},
                {12312, "BON'A PARTE - Test Environment"},
                {12316, "Linds A/S TestEnvironment"},
                {12335, "ReaMed A/S"}
            };
            return returnList;
        }
    }
}
