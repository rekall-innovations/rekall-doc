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

For example, consider the humble :ref:`pslist-APIPSList-plugin` plugin -
a simple plugin which just displays the list of running processes in
tabular form. Initially this plugin produced a number of columns such
as process name, pid etc. Some users required the binary path, and
that was added. Then some users requires restricing the listed
processed by various means, such as a list of pids, process name
regular expression, start time etc.

Then some users wanted to combine the output from several plugins in
some way. For example, show all the vad regions from a the "chrome"
process.

It soon became obvious that we could not just keep adding more and
more flags to each plugin to control the way the plugin worked. The
same kind of filtering was repeating in many plugins (e.g. filter by
process names) and it was difficult to anticipate how users would like
to combine plugins in the future.

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


Lets look at a simple EFilter query:

.. code-block:: sql

  select proc.name, pid from pslist() where pid > 4

This query contains three main parts:

1. The pslist() plugin will be executed and produce a set of
   rows. Each row contains several columns.
2. The filter condition follows the "where" operator and specifies a
   condition. EFilter will evaluate the condition on each row emitted
   from the plugin and only matching rows will be displayed.
3. The output is then produced in two columns which are derived from
   each emitted row.

Describing Plugins
------------------

In order for EFilter to work, each plugin must produce structured
output in a specified format. We have seen before that plugins produce
a sequence of rows, with each row having several columns. Each cell is
a specific type of object.

Let us examine the `pslist()` plugin again. To get information about
each plugin output we can use the :ref:`describe-Describe-plugin`
plugin::

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

.. note:: In Rekall each plugin is free to produce any output - the
          output types of each plugin are not defined in advance
          (since they might change depending on the profile, OS
          version etc). Therefore it is difficult to predict in
          advance what each column will contain.

          The describe plugin therefore needs to actually run the
          plugin and it inspects the output of the first row
          produced. While this works most of the time, it is often not
          possible to get a sensible result without supplying proper
          arguments. For example, consider the
          :ref:`glob-IRglob-plugin` plugin. When run with no
          arguments it does not produce any results (since there is
          nothing to glob). Therefore :ref:`describe-Describe-plugin`
          will produce incorrect results.

          To solve this predicament it is possible to run the
          describe() plugin with the `args` parameter, which should be
          a python dict of parameters to be passed to the plugin. This
          way the plugin maybe run with reasonable parameters and
          produce reasonable results.


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
arguments. Most Rekall plugins, however, take some form of
arguments. We can see the arguments that a plugin takes by consulting
`the plugin documentation`_ or by appending "?" to the name of the
plugin:

.. code-block:: text

  [1] Live (API) 21:12:35> pslist?
  file:            rekall-core/rekall/plugins/response/processes.py
  Plugin:          APIPslist (pslist)
  :                This is a Typed Plugin.
  Positional Args:   pids: One or more pids of processes to select. (type: ArrayIntParser)
  Keyword Args:
    profile:    Name of the profile to load. This is the filename of the profile found in the profiles directory. Profiles are searched in the profile path order (If specified we disable autodetection).
    proc_regex: A regex to select a process by name. (type: RegEx)
    verbosity:  An integer reflecting the amount of desired output: 0 = quiet, 10 = noisy. (type: IntParser)


It is possible to feed the result of an efilter query into the
parameters from another plugin. Here is a trivial example::

  [1] Live (API) 21:19:53> select * from pslist(pids: (select pid from pslist() where proc.name =~ "rekall"))
     proc       Name    pid  ppid  Thds Hnds       wow64               start                       binary
     -------------- ------- ----- ----- ---- ---- ----------------- --------------------- -----------------------------------
     rekall (7826)  rekall  7826  7746  105       False             2018-01-27 05:12:20Z  /home/mic/projects/Dev/bin/python3

Note the following about the subselect syntax:

1. Argument names are provided to the plugin with the ":"
   operator. This assigns the output of the sub-select as a list into
   the parameter.

2. The subselect must yield a single column. If the subselect yields
   more than one column, it is not clear which column should be
   assigned to the plugin parameter and Rekall will issue an error::

     [1] Live (API) 21:19:43> select * from pslist(pids: (select * from pslist() where proc.name =~ "rekall"))
     2018-01-26 21:19:43,526:CRITICAL:rekall.1:Invalid Args: pids invalid: Arg pids must be a list of integers.

3. The arg assigment operator tries to convert the subselect column
   into the type required by the parameter. This means that if the
   parameter expects an integer then the subselect should yield
   something which should be convertible to an integer::

     [1] Live (API) 21:26:02> select * from pslist(pids: (select proc.name from pslist() where proc.name =~ "rekall"))
     2018-01-26 21:26:02,643:CRITICAL:rekall.1:Invalid Args: pids invalid: invalid literal for int() with base 10: 'rekall'.

EFilter functions.
------------------

We have seen that EFilter offers operators to work on columns. In this
section we see some of the more common functions and operators the
language provides.

.. _timestamp-function:

timestamp
~~~~~~~~~

The timestamp function converts its argument into a timestamp
object. This allows Rekall to operate on the timestamp in a timezone
aware way, compare it to other times etc.


Examples
--------

The following are example queries which demonstrate how some plugins
may be stringed together to achieve powerful combinations.

Finding Processes launched by a certain user.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Rekall has the :ref:`tokens-GetSIDs-plugin` plugin which displays all the authorization
tokens possessed by each process. Rekall also automatically resolves
the token's SID to a username.

.. code-block:: text

   [1] hank.aff4 22:54:29> tokens()
   Process                                    Sid                    Comment
   -------------------------------------- ---------------- ----------------------------------
   0xfa8000c9e040 System                  4 S-1-5-18         Local System
   0xfa8000c9e040 System                  4 S-1-5-32-544     Administrators
   0xfa8000c9e040 System                  4 S-1-1-0          Everyone
   0xfa8000c9e040 System                  4 S-1-5-11         Authenticated Users
   0xfa8000c9e040 System                  4 S-1-16-16384     System Mandatory Level


Lets see all the processes started by "jessie":

.. code-block:: text

   [1] hank.aff4 22:56:14> select * from tokens() where Comment =~ 'User: jessie'
   Process                                    Sid                                     Comment
   ----------------------------------- ---------------------------------------------- -------------
   0xfa8002418440 regsvr32.exe     884 S-1-5-21-4270721788-567995706-2532315982-1003  User: jessie
   0xfa8001417720 explorer.exe    1512 S-1-5-21-4270721788-567995706-2532315982-1003  User: jessie
   0xfa8000f95b30 VBoxTray.exe    1964 S-1-5-21-4270721788-567995706-2532315982-1003  User: jessie
   0xfa8000fdc780 miranda64.exe   2208 S-1-5-21-4270721788-567995706-2532315982-1003  User: jessie
   0xfa80022e2230 dwm.exe         2520 S-1-5-21-4270721788-567995706-2532315982-1003  User: jessie
   0xfa8000f7d1b0 taskhost.exe    2596 S-1-5-21-4270721788-567995706-2532315982-1003  User: jessie
   0xfa8002376060 taskhost.exe    2848 S-1-5-21-4270721788-567995706-2532315982-1003  User: jessie

Lets view each process creation time and its full command line. The
Process column is not simply a string. It is a full blown Rekall
object which represents the kernel's _EPROCESS struct. We therefore
can dereference individual members of _EPROCESS and retrieve
additional information.

.. code-block:: text

   [1] hank.aff4 22:59:13> select Process, Process.CreateTime, Comment, Process.Peb.ProcessParameters.CommandLine from tokens() where Comment =~ 'User: jessie'
   Process                                CreateTime          Comment                        CommandLine
   ----------------------------------- --------------------- ------------- ---------------------------------------------------
   0xfa8002418440 regsvr32.exe     884 2015-08-10 02:00:45Z  User: jessie
   0xfa8001417720 explorer.exe    1512 2015-08-10 02:00:41Z  User: jessie  C:\Windows\Explorer.EXE
   0xfa8000f95b30 VBoxTray.exe    1964 2015-08-10 02:01:05Z  User: jessie  "C:\Windows\System32\VBoxTray.exe"
   0xfa8000fdc780 miranda64.exe   2208 2015-08-10 02:01:37Z  User: jessie  "C:\Program Files (x86)\Miranda IM\miranda64.exe"
   0xfa80022e2230 dwm.exe         2520 2015-08-10 02:00:41Z  User: jessie  "C:\Windows\system32\Dwm.exe"
   0xfa8000f7d1b0 taskhost.exe    2596 2015-08-10 02:13:51Z  User: jessie  "taskhost.exe"
   0xfa8002376060 taskhost.exe    2848 2015-08-10 02:00:40Z  User: jessie  "taskhost.77exe"


Find files modified in the last 2 days.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When Rekall is run in live mode, it can examine files on the local
filesystem. This is useful for incident response situations. One of
the more useful plugins available in live mode is the
:ref:`glob-IRGlob-plugin` plugin which enumerate files on the local
filesystem based on one or more glob expressions (similar to the shell
glob). According to the plugin documentation, we see that the plugin
accepts a repeated parameter called "globs" for all the glob
expressions. Let's see all the files in the /etc/ directory:

.. code-block:: text

   [1] Live (API) 23:49:05> select * from glob(globs: "/etc/*")
   path
   ----------------------------
   /etc/papersize
   /etc/logrotate.d
   /etc/mime.types
   /etc/kbd

Although the output appears to only contain a single column ("path"),
we can see that the path is actually an object which contains a lot of
information about each file.

.. code-block:: text

   [1] Live (API) 00:16:03> describe glob, args=dict(globs=["/etc/*"])
   Field                                               Type
   -------------------------------------------------- ----
   path                                               FileInformation
   . filename                                         FileSpec
   .. filesystem                                      str
   .. name                                            str
   .. path_sep                                        str
   . session                                          -
   . st_atime                                         float
   . st_ctime                                         float
   . st_dev                                           int
   . st_gid                                           Group
   .. gid                                             int
   .. group_name                                      str
   .. session                                         NoneType
   . st_ino                                           int
   . st_mode                                          Permissions
   . st_mtime                                         float
   . st_nlink                                         int
   . st_size                                          int
   . st_uid                                           User
   .. homedir                                         str
   .. session                                         NoneType
   .. shell                                           str
   .. uid                                             int
   .. username                                        str

In particular we see that the `path.st_mtime` is a float describing the file's modification time::

  [1] Live (API) 00:29:08> select path.st_mtime, path from glob(globs: "/etc/*")
  st_mtime                   path
  ------------------- ----------------------------
  1516590897.1290069  /etc/papersize
  1516687780.2982903  /etc/logrotate.d
  1446219570.0        /etc/mime.types

Since the field is a float, Rekall does not understand that it is
actually a timestamp, and therefore we can not do any time arithmetic
on it. We therefore need to explitely convert the modification time to
a timestamp using the :ref:`timestamp-function` function.

.. code-block:: text

   [1] Live (API) 00:31:50> select timestamp(path.st_mtime) as mtime, path from glob(globs: "/etc/*") where mtime > "2 days ago"
   mtime               path
   --------------------- -----------------
   2018-01-29 06:11:15Z  /etc/resolv.conf
   2018-01-29 06:11:15Z  /etc/timezone

1. Note the explicit conversion to a timestamp. This allows Rekall to apply time related operators on this column.
2. The column is aliased as "mtime", which appears as the title of the
   first column. More importantly, the alias can be used in further
   calculations (specifically inside the where clause).
3. Note the human readable time specification "2 days ago". Rekall
   supports such convenient expressions, as well as exactly formatted
   times.


.. _`the plugin documentation`: plugins
