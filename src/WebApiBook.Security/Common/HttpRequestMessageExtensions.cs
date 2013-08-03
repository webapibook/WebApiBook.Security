using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace WebApiBook.Security.Common
{
    public static class HttpRequestMessageExtensions
    {
        public static bool HasAuthorizationHeaderWithBasicScheme(this HttpRequestMessage req)
        {
            return req.Headers.Authorization != null
                   && req.Headers.Authorization.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase);
        }

        public static async Task<ClaimsPrincipal> TryGetPrincipalFromBasicCredentialsUsing(this HttpRequestMessage req, 
            Func<string,string,Task<ClaimsPrincipal>> validate)
        {
            string pair;
            try
            {
                pair = Encoding.UTF8.GetString(Convert.FromBase64String(req.Headers.Authorization.Parameter));
            }
            catch (FormatException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
            var ix = pair.IndexOf(':');
            if (ix == -1) return null;
            var username = pair.Substring(0, ix);
            var pw = pair.Substring(ix + 1);
            return await validate(username, pw);
        }
    }
}
