from ControlFlow import *

maze_string = """
+-+-----+
|X|     |
| | --+ |
| |   | |
| +-- | |
|     |#|
+-----+-+
"""

maze_code = generate_maze_code(maze_string)
exec(maze_code)
print(maze("DDDDRRRRUULLUURRRRDDDD"))