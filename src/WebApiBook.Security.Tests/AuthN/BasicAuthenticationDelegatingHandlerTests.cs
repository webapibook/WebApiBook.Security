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
    public class BasicAuthenticationDelegatingHandlerTests : BasicAuthenticationTestBase
    {
        public BasicAuthenticationDelegatingHandlerTests()
            : base(config => config.MessageHandlers.Add(new BasicAuthenticationDelegatingHandler(
                "myrealm", BasicAuthenticationTestBase.TestValidator)))
        { }
    }


}
