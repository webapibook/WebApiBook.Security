using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Cors;
using System.Web.Http;
using System.Web.Http.Cors;

namespace WebApiBook.Security.Diagrams
{
    [EnableCors(origins:"https://localhost",headers:"*",methods:"GET", PreflightMaxAge = 60)]
    public class ResourceController : ApiController
    {
        //...    
    }
}
