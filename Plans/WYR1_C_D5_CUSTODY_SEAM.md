# WYR1-C D5 custody seam

**Status:** D5 host substrate reached. Deepwyrm's primordial producer and
Wyrmroot's corresponding host-model/protocol/profile seams are implemented.
No selected product has yet pinned an exact pair or performed live WRBP V3
intake; that remains downstream product integration rather than a D5 guest
acceptance claim.

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

## Downstream selected-product integration seam

The producer no longer waits on creation, but its selected-product
four-capability output has not yet been consumed by an exact paired Wyrmroot
revision. The current Wyrmroot bootstrap/system-init production intake remains
the historical V2 three-capability path. A coordinated integration change must:

1. select WRBP V3 only for the D5 product and preserve every historical V1/V2
   profile unchanged;
2. validate all four received metadata records freshly;
3. retain the fourth local handle separately from `LoadAuthority` for the
   life of init; and
4. create the devmgr-generation TaskGroup beneath that domain, duplicate only
   `RESOURCE | INSPECT`, and MOVE it using a new explicit devmgr startup
   profile.

That future work belongs to the consuming selected-product milestone. It does
not authorize a C4 resource claim, DeviceResource/Interrupt bundle,
`DRIVER_READY`, UART, or selector evidence. In particular, this document makes
no live intake, claim, or guest-acceptance assertion; its Wyrmroot evidence is
limited to the D5 host protocol/profile and custody model.
