namespace dataarchaive.Models
{
    public class Order
    {
        public int Id { get; set; }
        public string OrderNo { get; set; }
        public string OrderName { get; set; }
        public bool IsArchived { get; set; }
       // public DateTime? ArchivedDate { get; set; }
    }
}
