using dataarchaive.Models;

namespace dataarchaive.Repositories
{
    public interface IOrderService
    {
        Task<List<Order>> GetActiveOrdersAsync();
        Task<List<ArchivedOrder>> GetArchivedOrdersAsync();
        Task AddOrderAsync(string orderNo, string orderName);
        Task ArchiveOrdersAsync(List<int> orderIds);
    }
}
