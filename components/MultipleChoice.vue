<template>
	<b-form @submit.prevent="handleSubmit">
		<!-- Korvaa tämä: -->
		<b-form-group label="Valitse hedelmät">
			<b-form-checkbox-group
				v-model="fruitCollection"
				:options="items"
				stacked
			/>
		</b-form-group>
		<!-- Tällä:
		<component
			v-for="part in parts"
			:key="part.order"
			:is="part.type"
		/-->
		<b-button type="submit" class="btn-primary">Lähetä</b-button>
	</b-form>
</template>

<script>
/* Kun otat dynaamisen komponentin käyttöön, poista kommentointi
	Muuten herjaisi "no-unused-components" eikä buildaa
const CBGroup = () => import('~/components/CBGroup.vue')
const RadioGroup = () => import('~/components/RadioGroup.vue')
const SelectElement = () => import('~/components/SelectElement.vue')
*/
export default {
	name: 'MultipleChoice',
	/* Sama kuin yllä.
	components: {
		CBGroup,
		RadioGroup
	},
	*/
	data() {
		return {
			items: [
				{ text: 'Apple', value: 'apple' },
				{ text: 'Orange', value: 'orange' },
				{ text: 'Mango', value: 'mango' },
				{ text: 'Cherry', value: 'cherry' }
			],
			fruitCollection: []
		}
	},
	methods: {
		handleSubmit() {
			alert(JSON.stringify(this.fruitCollection))
		}
	}
}
</script>
