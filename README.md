# Vivenu Auto-Checkin with Azure Function
Azure Function to automatically checkin tickets in vivenu which are sold via POS.

At the Moment it works like this:
1. Webhook on Event "ticket.created" to Azure Function
2. Azure Function checks if the Ticket was sold via POS
3. Azure Function sends an API request to vivenu to checkin the ticket