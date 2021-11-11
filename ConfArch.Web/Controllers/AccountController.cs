using Microsoft.AspNetCore.Mvc;
using ConfArch.Data.Repositories;
using ConfArch.Web.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;

namespace ConfArch.Web.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUserRepository userRepository;

        public AccountController(IUserRepository userRepository)
        {
            this.userRepository = userRepository;
        }
        
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = "/")      //Note that Whenever there is a redirect to the Login, it send the Url that was called before
        {                                                       //Login into ReturnUrl as Query String which we are storing in this variable
            return View(new LoginModel { ReturnUrl = returnUrl });
        }
        
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var user = userRepository.GetByUsernameAndPassword(model.Username, model.Password);
            if (user == null)
                return Unauthorized();

            var claims = new List<Claim>
            { 
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("FavoriteColor", user.FavoriteColor),
            };

            var identity = new ClaimsIdentity(claims, 
                CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal,
                new AuthenticationProperties { IsPersistent = model.RememberLogin });

            return LocalRedirect(model.ReturnUrl);      //Used LocalRedirect instead of just Redirect to prevent unauthorised Redirection to some other URL
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Redirect("/");
        }
    }
}
