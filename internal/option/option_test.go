package option

import (
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestApply(t *testing.T) {
	type Config struct {
		Flag bool
		TTL  time.Duration
	}

	tcs := []struct {
		cfg     Config
		options []func(*Config)
		want    Config
	}{
		{
			cfg:     Config{},
			options: nil,
			want:    Config{},
		},
		{
			cfg: Config{},
			options: []func(*Config){
				nil,
			},
			want: Config{},
		},
		{
			cfg: Config{},
			options: []func(*Config){
				func(c *Config) { c.Flag = true },
			},
			want: Config{Flag: true},
		},
		{
			cfg: Config{},
			options: []func(*Config){
				nil,
				func(c *Config) { c.Flag = true },
				func(c *Config) { c.TTL = time.Second },
			},
			want: Config{Flag: true, TTL: time.Second},
		},
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i+1), func(t *testing.T) {
			Apply(&tc.cfg, tc.options)
			if !reflect.DeepEqual(tc.want, tc.cfg) {
				t.Fatalf("want %+v, got %+v", tc.want, tc.cfg)
			}
		})
	}
}
