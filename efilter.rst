EFilter - A query language for Rekall.
======================================

The Rekall framework is plugin based. This is what makes it so
extensible. Developers can add many different plugins to implement
different analysis techniques and produce different data.

Historically, plugins had no restriction over the type of output they
produced. While some plugins put thought into producing structured
output, others produced output which was only usable by humans, since
it was largely unstructured. As the needs for automation increased, it
soon became obvious that plugin output needs to be machine parseable
in some way.

For example, consider the humble `pslist` plugin - a simple plugin
which just displays the list of running processes in tabular
form. Initially this plugin produced a number of columns such as
process name, pid etc. Some users required the binary path, and that
was added. Then some users requires restricing the listed processed by
various means, such as a list of pids, process name regular
expression, start time etc.

Then some users wanted to combine the output from several plugins in
some way. For example, show all the vad regions from a the "chrome"
process.

It soon became obvious that we could not just keep adding more and
more flags to each plugin to control the way the plugin worked. The
same kind of filtering was repeating in many plugins (e.g. filter by
process names) and it was difficult to anticipate how users would like
to combine plugins in the future.

Rekall as a search engine.
~~~~~~~~~~~~~~~~~~~~~~~~~~

We wanted to create a mechanism that gave users control over which
results they wanted to see, how to filter the output and how to
combine the output from several plugins together.

The idea of building a framework to facilitate arbitrary queries was
born. We chose to model the query language after SQL which is widely
understood, and this is how EFilter was born.

What is EFilter?
----------------

EFilter is an SQL like query language for combining, filtering and
customizing the output of Rekall plugins. Just like in SQL, EFilter
queries are used to generate a customized output, however, unlike a
database query, EFilter runs Rekall plugins to generate data
dynamically, rather than look at stored data.


Lets look at a simple EFilter query::

  select proc.name, pid from pslist() where pid > 4

This query contains three main parts:

1. The pslist() plugin will be executed and produce a set of
   rows. Each row contains several columns.
2. The filter condition follows the "where" operator and specifies a
   condition. EFilter will evaluate the condition on each row emitted
   from the plugin and only matching rows will be displayed.
3. The output is then produced in two columns which are derived from
   each emitted row.

Plugins
-------

In order for EFilter to work, each plugin must produce structured
output in a specified format. We have seen before that plugins produce
a sequence of rows, with each row having several columns. Each cell is
a specific type of object.

Let us examine the pslist() plugin again. To get information about
each plugin output we can use the `describe` plugin::

  [1] Live (API) 16:18:50> describe pslist, max_depth=1
  Field                                              Type
  -------------------------------------------------- ----
  proc                                               LiveProcess
  . as_dict                                          method
  . cmdline                                          list
  . connections                                      list
  . cpu_affinity                                     list
  . cpu_percent                                      float
  . cpu_times                                        pcputimes
  . create_time                                      float
  . cwd                                              str
  . environ                                          dict
  . exe                                              str
  . get_process_address_space                        method
  . gids                                             pgids
  Name                                               str
  pid                                                int
  ppid                                               int
  Thds                                               int
  wow64                                              bool
  start                                              UnixTimeStamp


In the above example, we see that the plugin generates a *Name*
columen with a type of string, *pid* and *ppid* columns which are
integers as well as a more complex type, such as a UnixTimeStamp.

We can also see the field *proc* which is of type *LiveProcess*. This
more complex type is like a python dictionary itself, and contains
multiple members.

We can apply operators on the cells emitted by a specific plugin to
generate the desired output. For example, suppose we wanted to show
the command line for each running process. We can see the *proc*
object contains a *cmdline* field, and so we can simply issue::

  select proc.name, proc.cmdline from pslist()

Note that the cmdline is a list (it is the process's argv), and so
Rekall will display it as such using the special annotation::

  [1] Live (API) 16:32:48> select proc.name, proc.cmdline from pslist() where proc.name =~ "rekall"
               cmdline                name
  ----------------------------------- -------
  - 0:                                rekall
    /home/mic/projects/Dev/bin/python3
  - 1:
    /home/mic/projects/Dev/bin/rekall
  - 2:
    -v
  - 3:
    --live
  - 4:
    API



Operator rules.
---------------

EFilter is type aware and will try to do the right thing with each
type if it makes sense. When the user applies an operator on a type,
the operator will attempt to do something sensible (or else it will
just return None). The operator should never raise an error.

For example consider the `=~` operator which means a regular
expression match. When we apply this operator on a single string, we
expect that it match that string::

  select * from pslist() where proc.name =~ "rekall"

If however we applied this operator on a list, we expect the row to
match if any of the list items matches::

  select * from pslist() where proc.cmdline =~ "--live"

Note that it is not an error to try to apply a regular expression to a
non-string - it simply will never match. Therefore the following query
will always return the empty set, since an integer can never match a
regular expression::

  select * from pslist() where proc.pid =~ "foobar"


Plugin arguments.
-----------------

In the queries above we just ran the pslist plugin with no
arguments. This
