# WYR1-C D5 custody seam

**Status:** Wyrmroot host-model and protocol/profile substrate reached; the
kernel-side selected-product producer remains a Deepwyrm D5 dependency.

## Reached Wyrmroot substrate

- `WRBP` V3 is an explicit four-capability primordial profile. Its fourth
  role is `ResourceDomainTaskGroup`; V1/V2 decoding and their two/three
  capability shapes remain unchanged.
- `WRLP` V1.7 `SupervisorResourceDomain` is the only `/system/init` startup
  profile with that fourth role. It carries root, bootfs, ordinary loader
  TaskGroup, then resource-domain TaskGroup, with exact broad custody rights
  `MODIFY | DUPLICATE | TRANSFER | INSPECT | RESOURCE`.
- `ResourceDomainCustody` is deliberately separate from `LoadAuthority`.
  The focused model accepts a `DevmgrGenerationDescendant` only and returns
  the reduced `RESOURCE | INSPECT` authority. It rejects init and unrelated
  membership, so no ordinary loader path represents claim authority.

## Exact remaining integration seam

The current primordial kernel sender and the current Wyrmroot bootstrap/system
init production intake remain the historical V2 three-capability path. They
must be switched together only after Deepwyrm D5 creates and sends the
kernel-minted resource-domain TaskGroup. The integration change must:

1. select WRBP V3 only for the D5 product and preserve every historical V1/V2
   profile unchanged;
2. validate all four received metadata records freshly;
3. retain the fourth local handle separately from `LoadAuthority` for the
   life of init; and
4. create the devmgr-generation TaskGroup beneath that domain, duplicate only
   `RESOURCE | INSPECT`, and MOVE it using a new explicit devmgr startup
   profile.

That future work is D5 custody integration only. It does not authorize C4
resource claim, DeviceResource/Interrupt bundle, `DRIVER_READY`, UART, or
selector evidence.
