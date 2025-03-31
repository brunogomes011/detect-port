/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/brunogomes011/detect-port/detect"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Run a port detect on the hosts",
	RunE: func(cmd *cobra.Command, args []string) error {
		hostsFile := viper.GetString("hosts-file")
		ports, err := cmd.Flags().GetStringSlice("ports")
		if err != nil {
			return err
		}
		proto, err := cmd.Flags().GetString("protocol")
		if err != nil {
			return err
		}
		return detectAction(os.Stdout, hostsFile, receiveRangePort(ports), proto)
	},
}

func init() {
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().StringSliceP("ports", "n", []string{"22", "80", "443"}, "ports to scan. Range port is allowed. Example: 443-445")
	detectCmd.Flags().StringP("protocol", "p", "tcp", "tcp or udp")
}

func detectAction(out io.Writer, hostsFile string, ports []int, proto string) error {
	hl := &detect.HostsList{}
	if err := hl.Load(hostsFile); err != nil {
		return err
	}
	results := detect.Run(hl, ports, proto)
	return printResults(out, results)
}

func printResults(out io.Writer, results []detect.Results) error {
	message := ""
	for _, r := range results {
		message += fmt.Sprintf("%s:", r.Host)
		if r.NotFound {
			message += fmt.Sprintf(" Host not found\n\n")
			continue
		}
		message += fmt.Sprintln()
		for _, p := range r.PortStates {
			message += fmt.Sprintf("\t %s Port: %d %s\n", p.Protocol, p.Port, p.Open)
		}
		message += fmt.Sprintln()
	}

	_, err := fmt.Fprint(out, message)
	return err
}

func receiveRangePort(ports []string) []int {
	ports_range := make([]string, 0)
	for _, v := range ports {
		if strings.Contains(v, "-") {
			helper_v := strings.Split(v, "-")
			max_num, err := strconv.Atoi(helper_v[len(helper_v)-1])
			if err != nil {
				fmt.Println("Port number is invalid:", err)
				os.Exit(1)
			}
			min_num, err := strconv.Atoi(helper_v[0])
			if err != nil {
				fmt.Println("Port number is invalid:", err)
				os.Exit(1)
			}
			if min_num < max_num {
				for j := 0; j <= (max_num - min_num); j++ {

					value_str := strconv.Itoa((min_num + j))
					ports_range = append(ports_range, value_str)

				}

			}
		} else {
			ports_range = append(ports_range, v)
		}

	}

	integers := make([]int, len(ports_range))

	for i, v := range ports_range {
		num, err := strconv.Atoi(v)
		if err != nil {
			fmt.Println("Error in the port num", err)
			os.Exit(1)
		}
		if num < 1 || num > 65535 {
			fmt.Println("Allowed ports should be between 1-65535")
			os.Exit(1)
		}
		integers[i] = num

	}
	return integers
}
