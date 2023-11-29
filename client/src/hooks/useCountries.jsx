import countries from "world-countries";

const formattedCountries = countries.map((country)=> ({
    value: country.name.common,
    label: `${country.name.common} ${country.flag}`,
    latlng: country.latlng,
    region: country.region
}))

const useCountries = ()=> {
    const getAll = ()=> formattedCountries;
    return {getAll}
}

export default useCountries