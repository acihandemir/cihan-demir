#include <stdio.h>
#include <stdlib.h>
#include <math.h>
int main()
{
   int n;
   int i;
   int a;
   i=1;

   printf("lutfen n degerini girin\n");
   scanf("%d",&n);

   while (i<n)
   {

       a =i*i*i;
        printf("kupler=%d",a);
        i++;
   }
   return 0;
}

