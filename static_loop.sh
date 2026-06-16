#!/bin/bash
# Requisito:
# apt install s-nail
 
mkdir -p /root/staticloop/relatorios
>/root/staticloop/relatorios/totais_staticloop.txt
for lista in `cat /root/staticloop/lista_TN_static_loop.txt`; do
    if [ -s /root/staticloop/relatorios/static_loop_$lista.txt ]; then
       cp /root/staticloop/relatorios/static_loop_$lista.txt /root/staticloop/relatorios/static_loop_antes_$lista.txt
    fi
    >/root/staticloop/relatorios/static_loop_$lista.txt
    for lista2 in `cat /root/staticloop/asns/$lista.txt`; do
        fping -gae $lista2 2>> /tmp/lista; cat /tmp/lista| grep -v "<-" |grep "Time Exceeded"|sort -u >> /root/staticloop/relatorios/static_loop_$lista.txt; rm -f /tmp/lista
    done
    if [ -s /root/staticloop/relatorios/static_loop_$lista.txt ]; then
        if [ -s /root/staticloop/relatorios/static_loop_antes_$lista.txt ]; then
           cat /root/staticloop/relatorios/static_loop_antes_$lista.txt|awk '{ print $5 " - " $11 }' > /tmp/velho_$lista
        fi
        cat /root/staticloop/relatorios/static_loop_$lista.txt|awk '{ print $5 " - " $11 }' > /tmp/novo_$lista
        total_sl="`cat /root/staticloop/relatorios/static_loop_$lista.txt|wc -l`"
        echo "$lista - $total_sl" >> /root/staticloop/relatorios/totais_staticloop.txt
        echo "STATIC LOOPS ATUAIS: $total_sl" > /root/staticloop/relatorios/relatorio_$lista.txt
        echo "====================" >> /root/staticloop/relatorios/relatorio_$lista.txt
        echo " " >> /root/staticloop/relatorios/relatorio_$lista.txt
        cat /tmp/novo_$lista >> /root/staticloop/relatorios/relatorio_$lista.txt
        echo " " >> /root/staticloop/relatorios/relatorio_$lista.txt
        if [ -s /root/staticloop/relatorios/static_loop_antes_$lista.txt ]; then
           echo "DIFERENCAS ANTERIORES" >> /root/staticloop/relatorios/relatorio_$lista.txt
           echo "=====================" >> /root/staticloop/relatorios/relatorio_$lista.txt
           echo " " >> /root/staticloop/relatorios/relatorio_$lista.txt
           echo "LADO ANTIGO                                                                           LADO NOVO" >> /root/staticloop/relatorios/relatorio_$lista.txt
           echo "===================================================================================================================================" >> /root/staticloop/relatorios/relatorio_$lista.txt
           echo " " >> /root/staticloop/relatorios/relatorio_$lista.txt
           diff -y --suppress-common-line /tmp/velho_$lista /tmp/novo_$lista >> /root/staticloop/relatorios/relatorio_$lista.txt
        fi
        if [ ! -s /root/staticloop/relatorios/relatorio_$lista.txt ]; then rm /root/staticloop/relatorios/relatorio_$lista.txt; fi
    else
        echo "$lista - 0" >> /root/staticloop/relatorios/totais_staticloop.txt
    fi
done
cat /root/staticloop/relatorios/totais_staticloop.txt | s-nail -s "STATIC LOOP - APENAS NET TURBO" $(for f in /root/staticloop/relatorios/relatorio_*.txt; do echo -a "$f"; done) gondim@ispfocus.net.br static.loop@netturbo.com.br
rm /tmp/velho_* /tmp/novo_* /root/staticloop/relatorios/relatorio_*.txt