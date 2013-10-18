using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Services;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using Thinktecture.IdentityModel.Extensions;

namespace WebApiBook.Security.Facts.Authz
{

    public static class AuthzClaimTypes
    {
        public const string RequestUri = "http://webapibook.net/claims/authz/requesturi";
        public const string RequestMethod = "http://webapibook.net/claims/authz/requestmethod";
    }

    public class UseClaimsAuthorizationManager : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            var principal = actionContext.Request.GetRequestContext().Principal;
            var claimsPrincipal = principal as ClaimsPrincipal;
            claimsPrincipal = claimsPrincipal ?? new ClaimsPrincipal(principal);

            var ctx = new System.Security.Claims.AuthorizationContext(
                claimsPrincipal,
                new Collection<Claim>
                {
                    new Claim(AuthzClaimTypes.RequestMethod, actionContext.Request.Method.ToString())
                },
                new Collection<Claim>
                {
                    new Claim(AuthzClaimTypes.RequestUri, actionContext.Request.RequestUri.ToString())
                });

            var manager =
                FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthorizationManager;
            if (!manager.CheckAccess(ctx))
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
            }
        }
    }


}
