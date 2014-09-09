================
Resource Cleaner
================



**WARNING** Be careful of running this script on production, as it really deletes all user's resources without any prompt.

Resource Cleaner wipes: instances, user images, volumes, snapshots from volumes, networks(subnets, routers, floating IPs), and sets quotas of user to zero.

NOTE: Only resources in Default project are deleted.

**How to run**

To run script, submit *admin name* as -a, *admin password* as -p, *Full keystone API endpoint* as -e and *username* as -u::

    python res_cleaner.py -a {admin username} -p {admin pass} -e {api endpoint} -u {username}

After this script worked, user must Log out and Log in to have an ability to buy new package.

**Known issues**

Keypairs are not deleted due to bug in nova working with keystone api v3.