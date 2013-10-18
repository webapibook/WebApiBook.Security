using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Cache;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using Newtonsoft.Json.Linq;

namespace WebApiBook.Security.ResourceServer1
{
    public class ResourceController : ApiController
    {
        [Authorize]
        public HttpResponseMessage Get()
        {
            var identity = User.Identity as ClaimsIdentity;
            return Request.CreateResponse(HttpStatusCode.OK, identity.Claims.Select(c => new {c.Type, c.Value}), Configuration.Formatters.JsonFormatter);
        }
    }
}
