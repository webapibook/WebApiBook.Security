using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Filters;
using System.Web.Http.Results;
using WebApiBook.Security.Common;

namespace WebApiBook.Security.AuthN
{

    public class BasicAuthenticationFilter : IAuthenticationFilter
    {
        private readonly Func<string, string, Task<ClaimsPrincipal>> _validator;
        private readonly string _realm;
        public bool AllowMultiple { get { return true; } }

        public BasicAuthenticationFilter(string realm, Func<string, string, Task<ClaimsPrincipal>> validator)
        {
            _validator = validator;
            _realm = "realm=" + realm;
        }

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var req = context.Request;
            if (req.HasAuthorizationHeaderWithBasicScheme())
            {
                var principal = await req.TryGetPrincipalFromBasicCredentialsUsing(_validator);
                if (principal != null)
                {
                    context.Principal = principal;
                }
                else
                {
                    // challenges will be added by the ChallengeAsync
                    context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0],
                        context.Request);
                }
            }
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ActionResultDelegate(context.Result, async (ct, next) =>
            {
                var res = await next.ExecuteAsync(ct);
                if (res.StatusCode == HttpStatusCode.Unauthorized)
                {
                    res.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Basic", _realm));
                }
                return res;
            });
            return Task.FromResult<object>(null);
        }
    }
}
