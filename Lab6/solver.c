#include <stdio.h>


void QuickSort(long* array, int firstIndex, int lastIndex) {
	if (firstIndex < lastIndex) {
		int pivot = firstIndex;

		for (int j = firstIndex; j < lastIndex; j++) {
			if (array[j] < array[lastIndex]) {
                long temp = array[pivot];
                array[pivot] = array[j];
                array[j] = temp;
				pivot++;
			}
		}

        long temp = array[pivot];
        array[pivot] = array[lastIndex];
        array[lastIndex] = temp;
		QuickSort(array, firstIndex, pivot - 1);
		QuickSort(array, pivot + 1, lastIndex);
	}
}


void sort(long* numbers, int n){
    QuickSort(numbers, 0, n-1);
}

int main(){
    long arr[] = {9,8,6,5,4,3,2,1};
    sort(arr, sizeof(arr)/sizeof(arr[0]));

    for(int i =0 ; i < sizeof(arr)/sizeof(arr[0]); i++)
        printf("%ld ", arr[i]);
    printf("\n");
}