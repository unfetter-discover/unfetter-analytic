while :
do
    sleep 15
    echo "beginning analysis"
#    spark-submit run_unfetter_analytic.py -c CAR-2013-02-008 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2013-03-001 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2013-04-002 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2013-05-002 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2013-10-001 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2013-10-002 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2014-03-006 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2014-04-003 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2014-05-002 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2014-11-002 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2014-11-004 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2014-11-008 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2016-04-002 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2016-04-003 -d min 1 -p
#    spark-submit run_unfetter_analytic.py -c CAR-2016-04-004 -d min 1 -p
    spark-submit run_unfetter_analytic.py -c CAR_2018_03_001 -d min 1 -p
done