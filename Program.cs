using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Sample
{
    class Program
    {
        public const string UserName = "soapadmin";             //place the webservice account username provided by the team here.        
        public const string Domain = "[portal].csod.com";     //place the portal name provided by the team here.
        public const string apiId = "wa2vbauugyvt"; //place the webservice ApiKey provided by the team here.
        public const string apiSecret = @"tDCBh1b8tDO8lGVvieNqVCFUZgsPm1OoxYW4OM3WgEt21BSBpICULBe9sYaNZAEoRLVe49Fply/zgjKBP6V4gg==";//place the webservice apiSecret provided by the team here.

        static void Main(string[] args)
        {
			System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls11
                                        | System.Net.SecurityProtocolType.Tls12;

            string Alias = UserName + Guid.NewGuid().ToString().Replace("-", "");

            var uri = new Uri(string.Format(@"https://" + Domain + "/services/api/sts/Session?userName={0}&alias={1}", UserName, Alias));
            var request = (HttpWebRequest)WebRequest.Create(uri);           

            request.Headers.Add("x-csod-date", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.000"));
            request.Headers.Add("x-csod-api-key", apiId);
            request.Method = "POST";

            var stringToSign = ConstructStringToSign(request.Method, request.Headers, uri.AbsolutePath);
            var sig = SignString512(stringToSign, apiSecret);
            request.Headers.Add("x-csod-signature", sig);

            request.ContentType = "text/xml";
            request.Timeout = 999999;
            request.ContentLength = 0;

            request.Accept = "text/xml";

            using (var response = request.GetResponse())
            {
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                {
                    string responseFromServer = reader.ReadToEnd();
                    Console.WriteLine(responseFromServer);
                }
            }

            Console.WriteLine();
            Console.WriteLine("Enter To Exit");
            Console.ReadLine();
        }
        public static string ConstructStringToSign(string httpMethod, NameValueCollection headers, string pathAndQuery)
        {
            StringBuilder stringToSign = new StringBuilder();
            var httpVerb = httpMethod.Trim() + "\n";
            var csodHeaders = headers.Cast<string>().Where(w => w.StartsWith("x-csod-"))
                                                    .Where(w => w != "x-csod-signature")
                                                    .Distinct()
                                                    .OrderBy(s => s)
                                                    .Aggregate(string.Empty, (a, l) => a + l.ToLower().Trim() + ":" + headers[l].Trim() + "\n");
            stringToSign.Append(httpVerb);
            stringToSign.Append(csodHeaders);
            stringToSign.Append(pathAndQuery);
            return stringToSign.ToString();
        }
        public static string SignString512(string stringToSign, string secretKey)
        {
            byte[] secretkeyBytes = Convert.FromBase64String(secretKey);
            byte[] inputBytes = Encoding.UTF8.GetBytes(stringToSign);
            using (var hmac = new HMACSHA512(secretkeyBytes))
            {
                byte[] hashValue = hmac.ComputeHash(inputBytes);
                return System.Convert.ToBase64String(hashValue);
            }
        }
    }
}
