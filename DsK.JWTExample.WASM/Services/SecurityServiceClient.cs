using Blazored.LocalStorage;
using DsK.JWTExample.Shared;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using static System.Net.WebRequestMethods;

namespace DsK.JWTExample.WASM.Services;

public class SecurityServiceClient
{
    private readonly ILocalStorageService _localStorageService;
    private readonly HttpClient _http;
    private readonly AuthenticationStateProvider _authenticationStateProvider;

    public SecurityServiceClient(ILocalStorageService localStorageService,
        HttpClient httpClient,
        AuthenticationStateProvider authenticationStateProvider)
    {
        _localStorageService = localStorageService;
        _http = httpClient;
        _authenticationStateProvider = authenticationStateProvider;
    }

    public async Task<string> Login(LoginRequest model)
    {
        try
        {
            var response = await _http.PostAsJsonAsync("Login", model);
            if (!response.IsSuccessStatusCode)
                return "Login Failed";

            var result = await response.Content.ReadFromJsonAsync<TokenModel>();

            if (result != null)
            {
                await _localStorageService.SetItemAsync("token", result.Token);
                await _localStorageService.SetItemAsync("refreshToken", result.RefreshToken);
                (_authenticationStateProvider as CustomAuthenticationStateProvider).Notify();
                return "Login Successful";
            }

            else
                return "Login Failed";

        }
        catch (Exception)
        {
            return "Login Failed";
        }

    }
    public async Task Logout()
    {
        await _localStorageService.RemoveItemAsync("token");
        await _localStorageService.RemoveItemAsync("refreshToken");
        (_authenticationStateProvider as CustomAuthenticationStateProvider).Notify();
    }
    public async Task PrepareBearerToken()
    {
        var token = await GetTokenAsync();
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", token);
    }
    public async Task<string> GetTokenAsync()
    {
        string token = await _localStorageService.GetItemAsync<string>("token");
        if (string.IsNullOrEmpty(token))
            return string.Empty;

        if (TokenHelpers.IsTokenExpired(token))
            token = await TryRefreshToken();

        return token;
    }
    private async Task<string> TryRefreshToken()
    {
        string token = await _localStorageService.GetItemAsync<string>("token");
        string refreshToken = await _localStorageService.GetItemAsync<string>("refreshToken");
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(refreshToken))
        {
            return string.Empty;
        }

        TokenModel tokenModel = new TokenModel(token, refreshToken);

        var response = await _http.PostAsJsonAsync("RefreshToken", tokenModel);
        if (!response.IsSuccessStatusCode)
        {
            return string.Empty;
        }

        var result = await response.Content.ReadFromJsonAsync<TokenModel>();
        if (result == null)
        {
            await _localStorageService.RemoveItemAsync("token");
            await _localStorageService.RemoveItemAsync("refreshToken");
            return string.Empty;
        }
        await _localStorageService.SetItemAsync("token", result.Token);
        await _localStorageService.SetItemAsync("refreshToken", result.RefreshToken);

        return result.Token;
    }
    public bool HasPermission(ClaimsPrincipal user, string permission)
    {
        var roles = user.Claims.Where(x => x.Type == ClaimTypes.Role).ToList();
        foreach (var role in roles)
        {
            if (role.Value == permission)
                return true;
        }
        return false;
    }
    public int GetUserId(ClaimsPrincipal user)
    {
        string userId = user.Claims.Where(_ => _.Type == "UserId").Select(_ => _.Value).FirstOrDefault();
        int userIdParsed = 0;
        int.TryParse(userId, out userIdParsed);
        return userIdParsed;
    }

}
