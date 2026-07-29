from collections import Counter
from pathlib import Path

from PIL import Image


IMAGE = Path(__file__).with_name("Art of Programming.png")
CODEL = 10

# (hue, lightness), using the order from the Piet specification.
PALETTE = {
    (255, 192, 192): (0, 0),
    (255, 0, 0): (0, 1),
    (192, 0, 0): (0, 2),
    (255, 255, 192): (1, 0),
    (255, 255, 0): (1, 1),
    (192, 192, 0): (1, 2),
    (192, 255, 192): (2, 0),
    (0, 255, 0): (2, 1),
    (0, 192, 0): (2, 2),
    (192, 255, 255): (3, 0),
    (0, 255, 255): (3, 1),
    (0, 192, 192): (3, 2),
    (192, 192, 255): (4, 0),
    (0, 0, 255): (4, 1),
    (0, 0, 192): (4, 2),
    (255, 192, 255): (5, 0),
    (255, 0, 255): (5, 1),
    (192, 0, 192): (5, 2),
}
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
DIRECTIONS = ((1, 0), (0, 1), (-1, 0), (0, -1))


def load_codels():
    image = Image.open(IMAGE).convert("RGB")
    width, height = image.size
    assert width % CODEL == height % CODEL == 0
    grid = []
    valid = set(PALETTE) | {WHITE, BLACK}
    for y in range(0, height, CODEL):
        row = []
        for x in range(0, width, CODEL):
            color, count = Counter(
                image.crop((x, y, x + CODEL, y + CODEL)).get_flattened_data()
            ).most_common(1)[0]
            # The executable frame consists of exact, solid Piet codels. Treat
            # the non-palette colors in the decorative center as walls.
            row.append(color if color in valid and count >= 50 else BLACK)
        grid.append(row)
    return grid


def color_block(grid, start):
    target = grid[start[1]][start[0]]
    todo = [start]
    seen = {start}
    while todo:
        x, y = todo.pop()
        for dx, dy in DIRECTIONS:
            point = (x + dx, y + dy)
            if (
                0 <= point[1] < len(grid)
                and 0 <= point[0] < len(grid[0])
                and point not in seen
                and grid[point[1]][point[0]] == target
            ):
                seen.add(point)
                todo.append(point)
    return seen


def exit_codel(block, dp, cc):
    dx, dy = DIRECTIONS[dp]
    # First maximize position along the DP. For CC-left, maximize position
    # along the vector obtained by rotating the DP counterclockwise.
    lx, ly = dy, -dx
    cc_sign = 1 if cc == 0 else -1
    return max(block, key=lambda p: (p[0] * dx + p[1] * dy,
                                     cc_sign * (p[0] * lx + p[1] * ly)))


def command(old, new):
    old_hue, old_light = PALETTE[old]
    new_hue, new_light = PALETTE[new]
    hue = (new_hue - old_hue) % 6
    light = (new_light - old_light) % 3
    return (
        ("noop", "push", "pop"),
        ("add", "subtract", "multiply"),
        ("divide", "mod", "not"),
        ("greater", "pointer", "switch"),
        ("duplicate", "roll", "in_number"),
        ("in_char", "out_number", "out_char"),
    )[hue][light]


def trunc_div(a, b):
    return abs(a) // abs(b) * (-1 if (a < 0) ^ (b < 0) else 1)


def run(
    grid,
    max_steps=1_000_000,
    history=None,
    start=(0, 0),
    initial_dp=0,
    initial_cc=0,
    initial_stack=None,
):
    position = start
    dp = initial_dp      # 0 is right
    cc = initial_cc      # 0 is left
    stack = list(initial_stack or ())
    output = []

    for _ in range(max_steps):
        source = position
        old_color = grid[position[1]][position[0]]
        block = color_block(grid, position)
        block_size = len(block)

        destination = None
        crossed_white = False
        trapped_in_white = False
        for attempt in range(8):
            x, y = exit_codel(block, dp, cc)
            dx, dy = DIRECTIONS[dp]
            x, y = x + dx, y + dy

            # White is traversed in a straight line and causes no command. If
            # a slide is blocked, retry from the last white codel after
            # toggling CC and rotating DP, as required by the 2008
            # clarification to the Piet specification.
            crossed_white = (
                0 <= y < len(grid)
                and 0 <= x < len(grid[0])
                and grid[y][x] == WHITE
            )
            if crossed_white:
                white_position = (x, y)
                white_states = set()
                while True:
                    state = (white_position, dp)
                    if state in white_states:
                        trapped_in_white = True
                        break
                    white_states.add(state)

                    dx, dy = DIRECTIONS[dp]
                    next_position = (
                        white_position[0] + dx,
                        white_position[1] + dy,
                    )
                    nx, ny = next_position
                    if (
                        0 <= ny < len(grid)
                        and 0 <= nx < len(grid[0])
                        and grid[ny][nx] == WHITE
                    ):
                        white_position = next_position
                        continue
                    if (
                        0 <= ny < len(grid)
                        and 0 <= nx < len(grid[0])
                        and grid[ny][nx] != BLACK
                    ):
                        x, y = next_position
                        break

                    cc ^= 1
                    dp = (dp + 1) % 4

                if trapped_in_white:
                    break

            if (
                0 <= y < len(grid)
                and 0 <= x < len(grid[0])
                and grid[y][x] != BLACK
            ):
                destination = (x, y)
                break

            if attempt % 2 == 0:
                cc ^= 1
            else:
                dp = (dp + 1) % 4

        if trapped_in_white:
            return ''.join(output), stack

        if destination is None:
            return "".join(output), stack

        new_color = grid[destination[1]][destination[0]]
        op = 'noop' if crossed_white else command(old_color, new_color)
        position = destination

        if history is not None:
            history.append((source, destination, op, block_size, tuple(stack)))

        if op == "push":
            stack.append(block_size)
        elif op == "pop":
            if stack:
                stack.pop()
        elif op == "add" and len(stack) >= 2:
            b, a = stack.pop(), stack.pop()
            stack.append(a + b)
        elif op == "subtract" and len(stack) >= 2:
            b, a = stack.pop(), stack.pop()
            stack.append(a - b)
        elif op == "multiply" and len(stack) >= 2:
            b, a = stack.pop(), stack.pop()
            stack.append(a * b)
        elif op == "divide" and len(stack) >= 2 and stack[-1] != 0:
            b, a = stack.pop(), stack.pop()
            stack.append(trunc_div(a, b))
        elif op == "mod" and len(stack) >= 2 and stack[-1] != 0:
            b, a = stack.pop(), stack.pop()
            stack.append(a % b)
        elif op == "not" and stack:
            stack.append(1 if stack.pop() == 0 else 0)
        elif op == "greater" and len(stack) >= 2:
            b, a = stack.pop(), stack.pop()
            stack.append(1 if a > b else 0)
        elif op == "pointer" and stack:
            dp = (dp + stack.pop()) % 4
        elif op == "switch" and stack:
            cc = (cc + stack.pop()) % 2
        elif op == "duplicate" and stack:
            stack.append(stack[-1])
        elif op == "roll" and len(stack) >= 2:
            rolls = stack.pop()
            depth = stack.pop()
            if depth > 0 and depth <= len(stack):
                rolls %= depth
                if rolls:
                    stack[-depth:] = stack[-rolls:] + stack[-depth:-rolls]
        elif op == "out_number" and stack:
            output.append(str(stack.pop()))
        elif op == "out_char" and stack:
            output.append(chr(stack.pop() % 0x110000))
        # The challenge does not require input; unavailable input is ignored.

    raise RuntimeError(f"program did not halt after {max_steps} steps")


if __name__ == "__main__":
    grid = load_codels()
    decoy, _ = run(grid)
    decoded, _ = run(
        grid,
        initial_cc=1,
        initial_stack=[ord('_'), ord('a')],
    )
    print(f'decoy: {decoy}')
    print(f'flag:  {decoded}')
    remaining_stack = []
    if remaining_stack:
        print(f"remaining stack: {remaining_stack}")
