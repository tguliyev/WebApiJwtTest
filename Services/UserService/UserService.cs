using System.Security.Claims;

namespace TestAspApiApp.Services.UserService;

public class UserService : IUserService
{
    private readonly IHttpContextAccessor httpContext;
    public UserService(IHttpContextAccessor httpContext)
    {
        this.httpContext = httpContext; 
    }
    public string GetMyName()
    {
        string res = string.Empty;
        if (httpContext != null)
            res = httpContext.HttpContext.User.FindFirstValue(ClaimTypes.Name);

        return res;
    }
}