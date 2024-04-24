class SelectGroup {

    constructor(id, selects){
        this.select = document.getElementById(id);

        let option = document.createElement("option");
            option.value = "";
            option.innerHTML = "Choose a product";
            this.select.appendChild(option);

        for (let brand in selects){

            let optgroup = document.createElement("optgroup");
            optgroup.label = brand;

            for (let product of selects[brand]){

                let option = document.createElement("option");
                option.value = product;
                option.innerHTML = product;
                optgroup.appendChild(option);

            }

            this.select.appendChild(optgroup);

        }

    }

}

class Select {

    constructor(id, selects){
        this.select = document.getElementById(id);

        let option = document.createElement("option");
        option.value = "";
        option.innerHTML = "Choose a brand";
        this.select.appendChild(option);

        for(let n of selects){

            let option = document.createElement("option");
                option.value = n;
                option.innerHTML = n;
                this.select.appendChild(option);

        }
    }

}
