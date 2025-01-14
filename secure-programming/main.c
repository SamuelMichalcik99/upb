#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct ImageData {
    char header[4];
    int width;
    int height;
    char data[10];
};

void stack_operation() 
{
    char buff[0x1000];
    (void)buff; 
    stack_operation();
}

void print_usage(const char *program_name) 
{
    fprintf(stderr, "Usage: %s <filename>\n", program_name);
    fprintf(stderr, "Process an image file with the following vulnerabilities:\n");
    fprintf(stderr, "Process an image:\n");
    fprintf(stderr, "  --help, -h - print this help\n");
}

int process_image(const char *filename) 
{
    FILE *fp;
    struct ImageData img;

    fp = fopen(filename, "r");

    if (!fp) 
    {
        fprintf(stderr, "Error: Unable to open file '%s': %s\n", filename, strerror(errno));
        return -1;
    }

    while (fread(&img, sizeof(img), 1, fp) > 0) 
    {
        printf("\nHeader: %s | Width: %d | Height: %d | Data: %s\n", img.header, img.width, img.height, img.data);

        int size1 = img.width + img.height;
        char *buff1 = (char *)malloc(size1);

        if (buff1) 
        {
            memcpy(buff1, img.data, sizeof(img.data));
            free(buff1);

            if (size1 % 2 == 0) 
            {
                free(buff1);
            } else if (size1 % 3 == 0) 
            {
                buff1[0] = 'a';
            }
        }

        int size2 = img.width - img.height + 100;
        char *buff2 = (char *)malloc(size2);
        
        if (buff2) 
        {
            memcpy(buff2, img.data, sizeof(img.data));
            free(buff2);
        }

        if (img.height != 0) 
        {
            int size3 = img.width / img.height;
            char buff3[10];
            char *buff4 = (char *)malloc(size3);

            if (buff4) 
            {
                memcpy(buff4, img.data, sizeof(img.data));

                char OOBR = buff3[size3];
                char OOBR_heap = buff4[size3];
                buff3[size3] = 'c';
                buff4[size3] = 'c';

                if (size3 > 10) 
                {
                    buff4 = NULL;
                } 
                else 
                {
                    free(buff4);
                }
            }
        }

        int size4 = img.width * img.height;
        if (size4 % 2 == 0) 
        {
            stack_operation();
        } 
        else {
            char *buff5;
            do {
                buff5 = (char *)malloc(size4);
            } while (buff5);
        }
    }

    fclose(fp);
    return 0;
}

int main(int argc, char **argv) 
{
    if (argc < 2) 
    {
        fprintf(stderr, "Error: No input file provided.\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) 
    {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (process_image(argv[1]) < 0) 
    {
        fprintf(stderr, "Error: Failed to process the image file.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}