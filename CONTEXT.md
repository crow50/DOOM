# D.O.O.M.

A self-hosted inventory system for people with more sites, shelves and bins than memory. Capture is one action; deciding where things belong can wait.

## Language

### Places

**Location**:
Any node in the tree of physical places an Item can be kept: a Site, Zone, Shelf or Bin.
_Avoid_: Container, place

**Site**:
A geographic Location, usually with an address. The top of a tree.

**Zone**:
A building or open yard within a Site.

**Shelf**:
Fixed storage within a Zone or Site: shelving, racking, a cabinet.

**Bin**:
A Location you can carry.
_Avoid_: Tote, crate (as separate terms)

### Problem space

**Doom pile**:
A heap of things left unfiled because deciding where each belongs is expensive, which migrates from table to chair to floor. The problem the product exists to remove.
_Avoid_: Clutter, backlog

### Items

**Item**:
A thing recorded in the system, kept in a Location or Unfiled. It needs a name or a photo, and nothing else.
_Avoid_: Asset, product

**Capture**:
Recording an Item in a single action, typically one photograph, with naming, counting and Filing all deferred.
_Avoid_: Add, create, entry

**Unfiled Item**:
An Item that has been captured but has no Location yet. The in-app form of a Doom pile.
_Avoid_: Loose item, inbox item

**Filing**:
Giving one or more Unfiled Items a Location. Always optional and always deferrable.
_Avoid_: Sorting, organizing
