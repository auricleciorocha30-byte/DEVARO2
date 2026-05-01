# Security Specification

## Data Invariants
1. `stores`: Represents the tenant. Only Admins/Gerentes can theoretically modify settings, but for strictness, `isActive` must remain boolean.
2. `users`: A waitstaff cannot exist without a valid `store_id`. Role must be strictly one of `GERENTE`, `ATENDENTE`, `ENTREGADOR`.
3. `products`: A product cannot be created without a valid `store_id` matching the user's `store_id`.
4. `orders`: Orders must have a valid `store_id`, `status` must follow state transitions or valid enums, `items` size must be bounded, and `total` must be numeric.
5. All relations to `store_id` must rigidly enforce `request.resource.data.store_id == existing().store_id` or `request.resource.data.store_id == get(/databases/$(database)/documents/users/$(request.auth.uid)).data.store_id`.

## The "Dirty Dozen" Payloads
1. **The Ghost Field (Shadow Update)**: Updating a product with `{"price": 10, "isVerified": true}`.
2. **State Shortcut**: Updating an order status from `AGUARDANDO` to `ENTREGUE` if the rules strictly restrict status jumps (though our Enums allow it, we just check Enum valid values).
3. **Identity Spoofing**: Creating a cash movement with `waitstaffName` different from the user's name or setting `store_id` to a different store.
4. **Denial of Wallet (Large Arrays)**: Sending an order with 200,000 items in the `items` array.
5. **Denial of Wallet (Large Strings)**: Setting a product description to a 10MB string.
6. **ID Poisoning**: Querying or creating a product where the ID is `../../../../etc/passwd`.
7. **Type Coercion**: Updating `total` on an order from a `number` to a `string` `"100.00"`.
8. **Role Escalation**: An `ATENDENTE` trying to update their own `role` to `GERENTE`.
9. **Blanket Read**: Fetching all customers across all stores without `where("store_id", "==", myStoreId)`.
10. **Immortal Field Tampering**: Updating the `createdAt` timestamp of a customer.
11. **Orphaned Write**: Creating a product with a `store_id` that doesn't exist in the `stores` collection.
12. **PII Leak**: Fetching customer `phone` or `cpf` globally.

## The Test Runner
A `firestore.rules.test.ts` will be provided once rules are finalized to execute these dirty dozen tests and ensure they all return `PERMISSION_DENIED`.
