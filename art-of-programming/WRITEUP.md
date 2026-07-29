# The Art of Programming

The image is not merely an abstract painting. Its border uses all 20 colors
from the Piet esoteric programming language, whose programs are designed to
look like Piet Mondrian paintings.

Each codel is a 10 by 10 pixel square, so the 600 by 600 image decodes to a
60 by 60 Piet program. Run the included interpreter with:

```powershell
python .\solve.py
```

The normal Piet initial state (DP right, CC left, empty stack) prints:

```text
ICS{This_is_Not_the_flag}
```

That is deliberately a decoy. The outer border actually contains two
intertwined execution lanes. Selecting the other lane with the codel chooser
set to right exposes the hidden message. It expects ASCII `_a` (`95, 97`)
on the stack; with that seed, execution prints:

```text
ICS{This_is_Mondarian_art}
```

The included solver executes both lanes and labels their outputs.

## Flag

`ICS{This_is_Mondarian_art}`
