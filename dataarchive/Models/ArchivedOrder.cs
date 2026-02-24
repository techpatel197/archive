namespace dataarchaive.Models
{
    public class ArchivedOrder
    {
        public int Id { get; set; }
        public string OrderNo { get; set; }
        public string OrderName { get; set; }
        public DateTime ArchivedDate { get; set; }
    }
}
