using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Hosting;
using WebApiBook.Security.AuthN;

namespace WebApiBook.Security.Tests.AuthN
{
    public class BasicAuthenticationFilterTest : BasicAuthenticationTestBase
    {
        public BasicAuthenticationFilterTest()
            : base(config => config.Filters.Add(new BasicAuthenticationFilter("myrealm", BasicAuthenticationTestBase.TestValidator)))
        {}
    }

    public class BasicAuthenticationDelegatingHandlerTest : BasicAuthenticationTestBase
    {
        public BasicAuthenticationDelegatingHandlerTest()
            : base(config => config.MessageHandlers.Add(new BasicAuthenticationDelegatingHandler(
                config.Services.GetService(typeof(IHostPrincipalService)) as IHostPrincipalService,
                "myrealm", BasicAuthenticationTestBase.TestValidator)))
        { }
    }


}
