using Blazored.LocalStorage;
using DsK.JWTExample.WASM;
using DsK.JWTExample.WASM.Services;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

//builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri("https://localhost:7129") }); //

/* ---Authentication--- */
//Add Authorization Core - To be able to use [CascadingAuthenticationState, AuthorizeRouteView, Authorizing], [AuthorizeView, NotAuthorized, Authorized], @attribute [Authorize]
builder.Services.AddAuthorizationCore();
//The CustomAuthenticationStateProvider is to be able to use tokens as the mode of authentication.
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationStateProvider>();
builder.Services.AddScoped<SecurityServiceClient>();

/* ---Manages saving to local storage--- */
builder.Services.AddBlazoredLocalStorage();

await builder.Build().RunAsync();
