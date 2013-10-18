using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace WebApiBook.Security.ResourceServer1
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
            config.Filters.Add(new HostAuthenticationFilter("Bearer"));
            
            app.UseJwtBearerAuthentication(new JwtBearerAuthenticationOptions
            {
                AllowedAudiences = new []
                {
                    "http://resourceserver.example"
                },
                IssuerSecurityTokenProviders = new []
                {
                    new SymmetricKeyIssuerSecurityTokenProvider("http://authzserver.example", "CDDK7wUSy1jKkw3ymWiPL/Ovgfgqid1QtBsFf47wCQE=")
                },
                
                Realm = "resourceserver.example",

                AuthenticationMode = AuthenticationMode.Passive
            });

            app.UseWebApi(config);
            
            Console.WriteLine("Configuration is done");
        }
    }
}
