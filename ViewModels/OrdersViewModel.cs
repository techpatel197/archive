using dataarchaive.Models;

namespace dataarchaive.ViewModels
{
    public class OrdersViewModel
    {
        public List<Order> ActiveOrders { get; set; }
        public List<ArchivedOrder> ArchivedOrders { get; set; }
    }
}
