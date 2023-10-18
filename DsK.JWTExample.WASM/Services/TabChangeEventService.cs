namespace DsK.JWTExample.WASM.Services
{
    public class TabChangeEventService
    {
        public event Func<Task> OnTabChangedAsync;

        public async Task TabChangedAsync()
        {
            if (OnTabChangedAsync != null)
            {
                await OnTabChangedAsync.Invoke();
            }
        }
    }
}
